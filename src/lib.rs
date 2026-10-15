pub mod clean_settings;
pub mod cleanup;
pub mod custom_clean;
pub mod domain;
pub mod drivers;
pub mod duplicates;
pub mod effects;
pub mod health;
pub mod instance;
#[cfg(windows)]
pub(crate) mod native_hash;
pub mod optimizer_identity;
#[cfg(windows)]
pub(crate) mod optimizer_pipe_io;
#[cfg(windows)]
pub(crate) mod optimizer_pipe_security;
pub mod optimizer_protocol;
pub mod optimizer_registration;
pub mod platform;
pub mod privacy;
pub mod programs;
pub mod recycle_bin;
pub mod scanner;
pub mod software;
pub mod startup;
pub mod store;
