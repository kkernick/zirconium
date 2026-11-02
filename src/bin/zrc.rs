#![allow(unused_crate_dependencies)]
//! Zirconium unlocks ZFS datasets on boot with a PCR measured AES key stored in the TPM.

use anyhow::Result;
use spawn::{Spawner, StreamMode};
use std::{
    fmt::Write,
    fs::{self, File},
    io::Write as _,
    path::Path,
};
use zirconium::config::Config;

fn main() -> Result<()> {
    let config = Config::load().unwrap_or_default();

    // Remove existing configurations.
    let dir = Path::new("/etc/systemd/system/zirconium.service.d");
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    fs::create_dir_all(dir)?;

    // Add a drop in to depend on each device
    config
        .pools
        .iter()
        .filter(|(_, d)| !d.is_empty())
        .try_for_each(|(pool, devices)| -> Result<()> {
            let out = dir.join(pool).with_extension("conf");
            let mut drop_in: String = String::from("[Unit]\n");
            for device in devices {
                let escaped = Spawner::abs("/usr/bin/systemd-escape")
                    .args(["--path", "--suffix=device", device])
                    .output(StreamMode::Pipe)
                    .spawn()?
                    .output_all()?;
                let _ = write!(drop_in, "Requires={escaped}");
                let _ = write!(drop_in, "After={escaped}");
            }
            File::create_new(out)?.write_all(drop_in.as_bytes())?;
            Ok(())
        })?;

    Ok(())
}
