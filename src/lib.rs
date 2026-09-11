//! Shared, platform-neutral functionality for Guardian agents.

#![deny(missing_debug_implementations)]

uniffi::setup_scaffolding!();

pub mod auth;
pub mod clock_integrity;
pub mod config;
pub mod dns;
pub mod i18n;
pub mod protocol;
pub mod reconnect;
pub mod screentime;
pub mod sentry;
pub mod update_verify;

pub use auth::generate_auth_signature;
pub use dns::{
    build_blocked_response, check_and_build_blocked_response, domain_is_allowed, domain_is_blocked,
    registrable_domain,
};
pub use protocol::{AgentConfig, AppAlert, ClientMessage, LinuxUser, ServerMessage};
pub use reconnect::{
    ActiveClientTx, AgentRuntime, CommandOutcome, HardwareInfo, UpdateOffer, build_alert_message,
    run_reconnect_loop,
};
pub use screentime::{HourSlot, UserTimeState, check_screentime_allowed};
pub use sentry::init_native_sentry;
