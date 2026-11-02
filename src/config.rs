#![allow(clippy::missing_docs_in_private_items, clippy::absolute_paths)]

use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::Path,
};
use thiserror::Error;

/// Configuration file errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to read configuration: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Invalid TPM configuration: {0}")]
    Invalid(&'static str),
}

const fn default_address() -> u32 {
    0x8101_0020
}

fn default_pcrs() -> Vec<u8> {
    vec![0, 7]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The address of the persistent handle to the AES key within the TPM
    #[serde(default = "default_address")]
    pub address: u32,

    /// The list of PCRs that should be used to seal encryption keys
    #[serde(default = "default_pcrs")]
    pub pcrs: Vec<u8>,

    /// The root dataset that should be mounted on /sysroot. This must
    /// have `mountpoint=legacy`, and you still need to include the pool
    /// in the pool list to have it imported.
    pub root: Option<String>,

    /// An explicit pool/dataset that contains user's homes. Defaults to the `ROOT_POOL/home`
    pub home_prefix: Option<String>,

    /// A list of pools that should be imported on boot, with the devices needed to import.
    /// Zirconium does not use the Cachefile, as upstream is phasing it out, and directly
    /// importing via devices is faster.
    pub pools: HashMap<String, Vec<String>>,
}
impl Config {
    /// Load the current configuration file at the given path.
    ///
    /// ## Errors
    /// If the configuration file does not exist, or is not valid.
    pub fn load() -> Result<Self, Error> {
        let path = Path::new("/etc/zirconium.toml");

        let config = if path.exists() {
            toml::from_str(&fs::read_to_string(path)?)?
        } else {
            Self::default()
        };

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.pcrs.is_empty() {
            return Err(Error::Invalid("at least one PCR must be selected"));
        }

        let mut seen = HashSet::new();

        for &pcr in &self.pcrs {
            if pcr > 23 {
                return Err(Error::Invalid("PCR indices must be between 0 and 23"));
            }
            if !seen.insert(pcr) {
                return Err(Error::Invalid("duplicate PCR index"));
            }
        }

        Ok(())
    }
}
impl Default for Config {
    fn default() -> Self {
        Self {
            address: default_address(),
            pcrs: default_pcrs(),
            root: None,
            home_prefix: None,
            pools: HashMap::new(),
        }
    }
}
