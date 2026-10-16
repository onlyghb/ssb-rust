pub mod app;
pub mod core;
pub mod link;
pub mod platform;
pub mod profile;
pub mod render;
pub mod subscription;
pub mod tui;

pub const VERSION: &str = match option_env!("SSB_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
