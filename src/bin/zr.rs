#![allow(unused_crate_dependencies)]
//! Zirconium unlocks ZFS datasets on boot with a PCR measured AES key stored in the TPM.

use anyhow::Result;
use bstr::{BString, ByteSlice};
use clap::Parser;
use spawn::{Spawner, StreamMode};
use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
    thread::sleep,
    time::Duration,
};
use tss_esapi::{Context, TctiNameConf, structures::SensitiveData, tcti_ldr::DeviceConfig};
use zirconium::{
    config::Config,
    pin, tpm,
    zfs::{self, init_libzfs},
};

#[derive(Parser, Default)]
#[command(name = "zr", version)]
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    /// Initialize the TPM-key--even if it already exists
    #[arg(short, long, default_value_t = false, env = "ZINIT")]
    pub init: bool,

    /// Reseal secrets after unlock, updating any stale values
    #[arg(short, long, default_value_t = false, env = "ZSEAL")]
    pub reseal: bool,

    /// Evict the TPM key
    #[arg(short, long, default_value_t = false, env = "ZEVICT")]
    pub evict: bool,

    /// Do not hash the PCRs used for decryption
    #[arg(short, long, default_value_t = false, env = "ZPERSIST")]
    pub persist: bool,

    /// Delete the zirconium properties on the specified dataset.
    #[arg(long)]
    pub purge: Option<String>,
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load().unwrap_or_default();

    // Remove the key from the TPM
    if cli.evict {
        let mut ctx = Context::new(TctiNameConf::Device(DeviceConfig::default()))?;
        let evicted = tpm::evict(&mut ctx, config.address)?;
        if evicted {
            println!("Evicted persistent handle {:#010x}", config.address);
        } else {
            println!("No persistent object at {:#010x}", config.address);
        }
        return Ok(());
    }

    // Try and re-use the same handle if possible.
    let zctx = init_libzfs()?;

    // Remove user properties
    if let Some(dataset) = cli.purge {
        let handle = zfs::Handle::new_with(&dataset, Rc::clone(&zctx))?;
        handle.inherit_user("zirconium:key")?;
        handle.inherit_user("zirconium:iv")?;
        return Ok(());
    }

    // Find all currently available pools
    let mut pools: HashMap<_, _> = zfs::Handle::pools()?
        .into_iter()
        .map(|p| (p.name().to_owned(), p))
        .collect();

    // Import pools that aren't already available.
    for pool in config.pools.keys() {
        if !pools.contains_key(pool.as_str()) {
            let mut handle = Spawner::abs("/usr/bin/zpool")
                .args(["import", "-f", pool])
                .preserve_env(true)
                .error(StreamMode::Pipe)
                .spawn()?;

            if handle.wait_and()? != 0 {
                eprint!("Failed to import {pool}: {}", handle.error_all()?);
            } else {
                pools.insert(pool.clone(), zfs::Handle::new_with(pool, Rc::clone(&zctx))?);
            }
        }
    }

    // Grab all encryption roots that do not have a loaded key yet
    let roots: HashSet<_> = pools
        .into_values()
        .filter_map(|pool| pool.datasets().ok())
        .flat_map(|datasets| {
            datasets
                .into_iter()
                .filter(|dataset| {
                    dataset
                        .get("keystatus")
                        .is_ok_and(|status| status == "unavailable")
                })
                .filter_map(|dataset| dataset.get("encryptionroot").ok())
        })
        .collect();

    if !roots.is_empty() {
        // Enroll the key if needed
        let mut ctx = Context::new(TctiNameConf::Device(DeviceConfig::default()))?;
        let enrolled = tpm::occupied(&mut ctx, config.address)?;
        if !enrolled || cli.init {
            tpm::enroll_wrapping_key(&mut ctx, &config, config.address)?;
        }

        'root_loop: for root in roots {
            let handle = zfs::Handle::new_with(root.to_str()?, Rc::clone(&zctx))?;
            let strategy = handle
                .get_user("zirconium:strategy")
                .map_or_else(|_| "pass".to_owned(), |bytes| bytes.to_string());

            // Do not do anything
            if strategy == "none" {
                continue;
            }

            // Only use the TPM if we...
            let seal = if strategy != "pass"                        // Haven't specified to only ask for password
                && enrolled                                         // Have a key enrolled
                && !cli.init                                        // Haven't enrolled a new key this session

                // Have the necessary materials to decrypt
                && let Ok(key) = handle.get_user("zirconium:key")
                && let Ok(iv) = handle.get_user("zirconium:iv")
            {
                let key: BString = hex::decode(key)?.into();
                let iv: BString = hex::decode(iv)?.into();

                match strategy.as_str() {
                    // Try and use the TPM
                    "tpm" | "both" => {
                        let plaintext = tpm::decrypt(
                            &mut ctx,
                            &config,
                            config.address,
                            key.as_bstr(),
                            iv.as_bstr(),
                        )?;

                        match handle.with_key(&plaintext) {
                            Ok(()) => continue,
                            Err(e) => {
                                eprint!("Failed to decrypt {}: {e}", handle.name());

                                // If we only use the TPM, do not try manual entry
                                if strategy == "tpm" {
                                    continue;
                                }
                            }
                        }
                    }

                    // Get the PIN, and decrypt the output from the TPM
                    "enhanced" => {
                        if let Ok(ciphertext) = pin::unseal(
                            key.as_bstr(),
                            &format!("Enter sealing PIN for {root}"),
                            root.iter().as_slice(),
                        ) && let Ok(plaintext) = tpm::decrypt(
                            &mut ctx,
                            &config,
                            config.address,
                            ciphertext.as_bstr(),
                            iv.as_bstr(),
                        ) && handle.with_key(&plaintext).is_ok()
                        {
                            continue;
                        }
                        eprintln!("Failed to unseal {}", handle.name());
                    }
                    e => eprintln!("Unknown strategy for {}: {e}", handle.name()),
                }
                false
            } else {
                true
            };

            // If TPM was not used/failed, manual entry
            let mut x = 1;
            let password = loop {
                let password: SensitiveData = Spawner::abs("/usr/bin/systemd-ask-password")
                    .args(["-n", &format!("Enter encryption key for {root}")])
                    .output(StreamMode::Pipe)
                    .spawn()?
                    .output_all()?
                    .into_bytes()
                    .try_into()?;
                match handle.with_key(&password) {
                    Ok(()) => break password,
                    Err(e) => {
                        eprint!("{e}");
                        if x > 5 {
                            continue 'root_loop;
                        }
                        sleep(Duration::from_secs(x));
                        x = x.saturating_add(1);
                    }
                }
            };

            // If we need to reseal the secret, encrypt the key and store in the user property
            if (seal || cli.reseal) && strategy != "pass" {
                println!("Sealing password for {} against TPM", handle.name());
                let iv: BString = tpm::generate_bytes(&mut ctx, 16)?.value().into();
                let mut ciphertext =
                    tpm::encrypt(&mut ctx, &config, config.address, &password, iv.as_bstr())?;
                handle.set_user(
                    "zirconium:iv",
                    BString::from(hex::encode(iv.as_slice())).as_bstr(),
                )?;

                // Ask for a PIN and use it to encrypt the key
                if strategy == "enhanced" {
                    ciphertext = pin::seal(
                        &mut ctx,
                        &ciphertext,
                        &format!("Enter a sealing pin for {}", handle.name()),
                        root.iter().as_slice(),
                    )?;
                }
                handle.set_user(
                    "zirconium:key",
                    BString::from(hex::encode(ciphertext.as_slice())).as_bstr(),
                )?;
            }
        }

        // Hash the PCRs
        if !cli.persist {
            tpm::wipe(&mut ctx, &config)?;
        }
    }

    // Mount the sysroot
    if let Some(root) = config.root
        && let Ok(handle) = zfs::Handle::new_with(&root, Rc::clone(&zctx))
        && !handle.is_mounted()
    {
        handle.mount("/sysroot")?;
    }

    Ok(())
}
