//! Native Sentry initialization used by the `UniFFI` consumer.

#[uniffi::export]
pub fn init_native_sentry() {
    if let Some(dsn) = option_env!("SENTRY_DSN") {
        if !dsn.is_empty() {
            let options = sentry::ClientOptions {
                release: Some(env!("CARGO_PKG_VERSION").into()),
                auto_session_tracking: true,
                ..Default::default()
            };
            let guard = sentry::init((dsn, options));
            if guard.is_enabled() {
                std::mem::forget(guard);
            }
        }
    }
}
