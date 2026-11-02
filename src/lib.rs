#![allow(unused_crate_dependencies)]

pub mod config;
pub mod pin;
pub mod tpm;
pub mod zfs;

pub static CONFIG_PATH: &str = "/etc/zirconium.conf";
