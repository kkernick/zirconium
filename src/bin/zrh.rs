#![allow(unused_crate_dependencies)]

use anyhow::{Result, anyhow};
use spawn::Spawner;
use std::{
    borrow::Cow,
    env,
    io::{Read, stdin},
};
use tss_esapi::structures::SensitiveData;
use zirconium::{config::Config, zfs};

fn main() -> Result<()> {
    let config = Config::load().unwrap_or_default();

    // Grab the needed variables
    let op = env::var("PAM_TYPE")?;
    let user = env::var("PAM_USER")?;

    // Use the home prefix if one is defined.
    let prefix = if let Some(prefix) = &config.home_prefix {
        Cow::Borrowed(prefix.as_str())
    } else if let Some(root) = &config.root {
        let pool = match root.find('/') {
            Some(i) => &root[..i],
            None => root,
        };
        Cow::Owned(format!("{pool}/home"))
    } else {
        return Err(anyhow!("A root dataset or home prefix is required!"));
    };

    let name = format!("{prefix}/{user}");
    if let Ok(dataset) = zfs::Handle::new(&name)
        && op == "auth"
    {
        // If we aren't our own encryption root, abort.
        if dataset.get("encryptionroot")? != name.as_bytes() {
            return Err(anyhow!("Home dataset must be its own encryption root!"));
        }

        // If the key isn't available, load it from the exposed auth token
        if dataset.get("keystatus")? == b"unavailable" {
            let mut pass = Vec::new();
            stdin().read_to_end(&mut pass)?;
            let pass = SensitiveData::try_from(pass)?;
            dataset.with_key(&pass)?;
        }

        // If the home dataset isn't mounted, mount it.
        if !dataset.is_mounted() {
            let rc = Spawner::abs("/usr/bin/zfs")
                .args(["mount", "-R", &name])
                .spawn()?
                .wait()?;
            if rc != 0 {
                return Err(anyhow!("Failed to unload key!"));
            }
        }
    }

    Ok(())
}
