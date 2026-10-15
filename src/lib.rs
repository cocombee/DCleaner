pub mod brand;
pub mod clean_settings;
pub mod cleanup;
pub mod cloud;
pub mod cloud_actions;
pub mod cloud_auth;
pub mod cloud_drive;
pub mod cloud_dropbox;
pub mod cloud_gmail;
pub mod cloud_http;
pub mod cloud_inventory;
pub mod cloud_onedrive;
pub mod cloud_store;
pub mod cloud_vault;
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
pub(crate) mod optimizer_intents;
pub mod optimizer_inventory;
#[cfg(windows)]
pub(crate) mod optimizer_pipe_io;
#[cfg(windows)]
pub(crate) mod optimizer_pipe_security;
pub mod optimizer_protocol;
pub mod optimizer_registration;
#[cfg(windows)]
pub(crate) mod optimizer_registry_tx;
pub(crate) mod optimizer_requests;
pub mod platform;
pub mod privacy;
pub mod programs;
pub mod recycle_bin;
pub mod scanner;
pub mod software;
pub mod startup;
pub mod startup_removal;
pub mod store;
pub mod support;
