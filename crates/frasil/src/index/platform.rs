//! The wall clock, by platform.

/// Milliseconds since the Unix epoch, by this device's wall clock.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub(crate) fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Milliseconds since the Unix epoch, by the browser's clock.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub(crate) fn now_millis() -> i64 {
    js_sys::Date::now() as i64
}
