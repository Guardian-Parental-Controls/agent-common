//! Wall-clock tamper detection via boottime cross-check and optional NTP.

use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const DEFAULT_THRESHOLD_SECS: i64 = 300;
pub const DEFAULT_CLEAR_CHECKS: u8 = 2;
pub const DEFAULT_NTP_HOST: &str = "pool.ntp.org";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    Boottime,
    Ntp,
    Both,
}

impl DetectionSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Boottime => "boottime",
            Self::Ntp => "ntp",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedClockIntegrity {
    pub baseline_wall_ms: i64,
    pub baseline_boottime_ms: i64,
    pub tamper_active: bool,
    pub consecutive_passing_checks: u8,
    pub otp_override_active: bool,
    #[serde(default = "default_threshold_secs")]
    pub threshold_secs: i64,
}

const fn default_threshold_secs() -> i64 {
    DEFAULT_THRESHOLD_SECS
}

impl Default for PersistedClockIntegrity {
    fn default() -> Self {
        Self {
            baseline_wall_ms: 0,
            baseline_boottime_ms: 0,
            tamper_active: false,
            consecutive_passing_checks: 0,
            otp_override_active: false,
            threshold_secs: DEFAULT_THRESHOLD_SECS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickStatus {
    Ok,
    TamperDetected,
    TamperCleared,
}

#[derive(Debug, Clone)]
pub struct TickOutcome {
    pub status: TickStatus,
    pub skew_seconds: i64,
    pub detection_source: Option<DetectionSource>,
    pub tamper_active: bool,
    pub expected_wall_ms: i64,
}

#[derive(Debug)]
pub struct ClockIntegrityState {
    inner: PersistedClockIntegrity,
}

impl ClockIntegrityState {
    pub fn new(persisted: PersistedClockIntegrity) -> Self {
        Self { inner: persisted }
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        if json.trim().is_empty() {
            return Ok(Self::new(PersistedClockIntegrity::default()));
        }
        serde_json::from_str(json)
            .map(Self::new)
            .map_err(|error| format!("invalid clock integrity state: {error}"))
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(&self.inner)
            .map_err(|error| format!("failed to serialize clock integrity state: {error}"))
    }

    pub fn tamper_active(&self) -> bool {
        self.inner.tamper_active && !self.inner.otp_override_active
    }

    pub fn otp_override_active(&self) -> bool {
        self.inner.otp_override_active
    }

    pub fn set_otp_override(&mut self, active: bool) {
        self.inner.otp_override_active = active;
        if active {
            self.inner.tamper_active = false;
            self.inner.consecutive_passing_checks = 0;
        }
    }

    pub fn threshold_ms(&self) -> i64 {
        self.inner.threshold_secs.saturating_mul(1000)
    }

    pub fn trusted_wall_ms(&self, boottime_ms: i64) -> i64 {
        let delta = boottime_ms.saturating_sub(self.inner.baseline_boottime_ms);
        self.inner.baseline_wall_ms.saturating_add(delta)
    }

    pub fn tick(&mut self, wall_ms: i64, boottime_ms: i64, ntp_ms: Option<i64>) -> TickOutcome {
        if self.inner.baseline_wall_ms == 0 && self.inner.baseline_boottime_ms == 0 {
            self.rebaseline(wall_ms, boottime_ms, ntp_ms);
            return outcome(TickStatus::Ok, 0, None, self.tamper_active(), wall_ms);
        }
        if boottime_ms < self.inner.baseline_boottime_ms {
            return self.handle_reboot(wall_ms, boottime_ms, ntp_ms);
        }

        let expected_wall_ms = self.trusted_wall_ms(boottime_ms);
        let boottime_skew_ms = (wall_ms - expected_wall_ms).abs();
        let boottime_breach = boottime_skew_ms > self.threshold_ms();
        let ntp_skew_ms = ntp_ms.map_or(0, |ntp| (wall_ms - ntp).abs());
        let ntp_breach = ntp_ms.is_some() && ntp_skew_ms > self.threshold_ms();
        let detection_source = match (boottime_breach, ntp_breach) {
            (true, true) => Some(DetectionSource::Both),
            (true, false) => Some(DetectionSource::Boottime),
            (false, true) => Some(DetectionSource::Ntp),
            (false, false) => None,
        };

        if boottime_breach || ntp_breach {
            let was_active = self.inner.tamper_active;
            self.inner.tamper_active = true;
            self.inner.consecutive_passing_checks = 0;
            self.inner.otp_override_active = false;
            return outcome(
                if was_active {
                    TickStatus::Ok
                } else {
                    TickStatus::TamperDetected
                },
                boottime_skew_ms.max(ntp_skew_ms).saturating_add(999) / 1000,
                detection_source,
                true,
                expected_wall_ms,
            );
        }

        if self.inner.tamper_active {
            self.inner.consecutive_passing_checks =
                self.inner.consecutive_passing_checks.saturating_add(1);
            if self.inner.consecutive_passing_checks >= DEFAULT_CLEAR_CHECKS {
                self.inner.tamper_active = false;
                self.inner.consecutive_passing_checks = 0;
                self.rebaseline(wall_ms, boottime_ms, ntp_ms);
                return outcome(TickStatus::TamperCleared, 0, None, false, wall_ms);
            }
            return outcome(TickStatus::Ok, 0, None, true, expected_wall_ms);
        }

        self.rebaseline(wall_ms, boottime_ms, ntp_ms);
        outcome(TickStatus::Ok, 0, None, false, expected_wall_ms)
    }

    fn handle_reboot(
        &mut self,
        wall_ms: i64,
        boottime_ms: i64,
        ntp_ms: Option<i64>,
    ) -> TickOutcome {
        let was_tamper = self.inner.tamper_active;
        self.inner.tamper_active = false;
        self.inner.consecutive_passing_checks = 0;
        self.rebaseline(wall_ms, boottime_ms, ntp_ms);

        if let Some(ntp) = ntp_ms {
            let ntp_skew_ms = (wall_ms - ntp).abs();
            if ntp_skew_ms > self.threshold_ms() {
                self.inner.tamper_active = true;
                return outcome(
                    TickStatus::TamperDetected,
                    ntp_skew_ms.saturating_add(999) / 1000,
                    Some(DetectionSource::Ntp),
                    true,
                    wall_ms,
                );
            }
        }

        outcome(
            if was_tamper {
                TickStatus::TamperCleared
            } else {
                TickStatus::Ok
            },
            0,
            None,
            self.tamper_active(),
            wall_ms,
        )
    }

    fn rebaseline(&mut self, wall_ms: i64, boottime_ms: i64, ntp_ms: Option<i64>) {
        self.inner.baseline_wall_ms = ntp_ms
            .filter(|ntp| (wall_ms - ntp).abs() <= self.threshold_ms())
            .unwrap_or(wall_ms);
        self.inner.baseline_boottime_ms = boottime_ms;
    }
}

fn outcome(
    status: TickStatus,
    skew_seconds: i64,
    detection_source: Option<DetectionSource>,
    tamper_active: bool,
    expected_wall_ms: i64,
) -> TickOutcome {
    TickOutcome {
        status,
        skew_seconds,
        detection_source,
        tamper_active,
        expected_wall_ms,
    }
}

#[cfg(target_os = "linux")]
pub fn boottime_ms() -> Result<i64, String> {
    use std::mem::MaybeUninit;

    let mut timestamp = MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `clock_gettime` initializes the pointed-to timespec when it succeeds.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, timestamp.as_mut_ptr()) };
    if result != 0 {
        return Err(format!(
            "clock_gettime(CLOCK_BOOTTIME) failed: errno {result}"
        ));
    }
    // SAFETY: A successful `clock_gettime` call initialized `timestamp`.
    let timestamp = unsafe { timestamp.assume_init() };
    Ok(timestamp.tv_sec * 1000 + timestamp.tv_nsec / 1_000_000)
}

#[cfg(target_os = "windows")]
pub fn boottime_ms() -> Result<i64, String> {
    use windows_sys::Win32::System::WindowsProgramming::QueryInterruptTime;

    let mut interrupt_100ns = 0_u64;
    // SAFETY: The pointer refers to an initialized, writable `u64`.
    unsafe {
        QueryInterruptTime(&mut interrupt_100ns);
    }
    Ok((interrupt_100ns / 10_000) as i64)
}

#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
pub fn boottime_ms() -> Result<i64, String> {
    Err("boottime_ms is not available on this platform".to_owned())
}

pub const FILETIME_EPOCH_DIFF_100NS: u64 = 11_644_473_600_000_000;

pub fn filetime_to_unix_ms(low: u32, high: u32) -> i64 {
    let filetime = u64::from(high) << 32 | u64::from(low);
    let unix_100ns = filetime.saturating_sub(FILETIME_EPOCH_DIFF_100NS);
    i64::try_from(unix_100ns / 10_000).unwrap_or(i64::MAX)
}

#[cfg(target_os = "linux")]
pub fn wall_clock_ms() -> Result<i64, String> {
    use std::mem::MaybeUninit;

    let mut timestamp = MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `clock_gettime` initializes the pointed-to timespec when it succeeds.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, timestamp.as_mut_ptr()) };
    if result != 0 {
        return Err(format!(
            "clock_gettime(CLOCK_REALTIME) failed: errno {result}"
        ));
    }
    // SAFETY: A successful `clock_gettime` call initialized `timestamp`.
    let timestamp = unsafe { timestamp.assume_init() };
    Ok(timestamp.tv_sec * 1000 + timestamp.tv_nsec / 1_000_000)
}

#[cfg(target_os = "windows")]
pub fn wall_clock_ms() -> Result<i64, String> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;

    let mut filetime = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: The pointer refers to an initialized, writable `FILETIME`.
    unsafe {
        GetSystemTimePreciseAsFileTime(&mut filetime);
    }
    Ok(filetime_to_unix_ms(
        filetime.dwLowDateTime,
        filetime.dwHighDateTime,
    ))
}

#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
pub fn wall_clock_ms() -> Result<i64, String> {
    Err("wall_clock_ms is not available on this platform".to_owned())
}

const NTP_EPOCH_OFFSET_SECS: u64 = 2_208_988_800;

pub async fn query_ntp_ms(host: &str, timeout: Duration) -> Result<i64, String> {
    use tokio::{net::UdpSocket, time};

    let address = format!("{host}:123");
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|error| format!("failed to bind UDP socket: {error}"))?;
    socket
        .connect(&address)
        .await
        .map_err(|error| format!("failed to connect to {address}: {error}"))?;

    let mut packet = [0_u8; 48];
    packet[0] = 0x1B;
    socket
        .send(&packet)
        .await
        .map_err(|error| format!("failed to send SNTP request: {error}"))?;
    let received = time::timeout(timeout, socket.recv(&mut packet))
        .await
        .map_err(|_| "SNTP query timed out".to_owned())?
        .map_err(|error| format!("failed to receive SNTP response: {error}"))?;
    if received < 48 {
        return Err("SNTP response too short".to_owned());
    }

    let seconds = u64::from(u32::from_be_bytes([
        packet[40], packet[41], packet[42], packet[43],
    ]));
    let fraction = u64::from(u32::from_be_bytes([
        packet[44], packet[45], packet[46], packet[47],
    ]));
    if seconds < NTP_EPOCH_OFFSET_SECS {
        return Err("invalid SNTP timestamp".to_owned());
    }
    let unix_ms =
        (seconds - NTP_EPOCH_OFFSET_SECS) * 1000 + (fraction * 1000) / u64::from(u32::MAX);
    i64::try_from(unix_ms).map_err(|_| "SNTP timestamp is out of range".to_owned())
}

pub async fn fetch_tick_inputs() -> Result<(i64, i64, Option<i64>), String> {
    let wall_ms = wall_clock_ms()?;
    let boottime_ms = boottime_ms()?;
    let ntp_ms = query_ntp_ms(DEFAULT_NTP_HOST, Duration::from_secs(3))
        .await
        .ok();
    Ok((wall_ms, boottime_ms, ntp_ms))
}

pub fn apply_tick(
    state: &mut ClockIntegrityState,
    wall_ms: i64,
    boottime_ms: i64,
    ntp_ms: Option<i64>,
) -> TickOutcome {
    state.tick(wall_ms, boottime_ms, ntp_ms)
}

pub async fn perform_tick(state: &mut ClockIntegrityState) -> Result<TickOutcome, String> {
    let (wall_ms, boottime_ms, ntp_ms) = fetch_tick_inputs().await?;
    Ok(apply_tick(state, wall_ms, boottime_ms, ntp_ms))
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ClockIntegrityTickResult {
    pub status: String,
    pub skew_seconds: i64,
    pub detection_source: String,
    pub tamper_active: bool,
    pub expected_wall_ms: i64,
    pub persisted_json: String,
}

#[uniffi::export]
pub fn clock_integrity_init(persisted_state_json: String) -> String {
    ClockIntegrityState::from_json(&persisted_state_json)
        .and_then(|state| state.to_json())
        .unwrap_or_else(|_| {
            serde_json::to_string(&PersistedClockIntegrity::default()).unwrap_or_default()
        })
}

#[uniffi::export]
pub fn clock_integrity_tick(
    persisted_state_json: String,
    wall_ms: i64,
    boottime_ms: i64,
    ntp_ms: i64,
) -> ClockIntegrityTickResult {
    let ntp = (ntp_ms >= 0).then_some(ntp_ms);
    let mut state = ClockIntegrityState::from_json(&persisted_state_json)
        .unwrap_or_else(|_| ClockIntegrityState::new(PersistedClockIntegrity::default()));
    let tick = state.tick(wall_ms, boottime_ms, ntp);
    let status = match tick.status {
        TickStatus::Ok => "ok",
        TickStatus::TamperDetected => "tamper_detected",
        TickStatus::TamperCleared => "tamper_cleared",
    };

    ClockIntegrityTickResult {
        status: status.to_owned(),
        skew_seconds: tick.skew_seconds,
        detection_source: tick
            .detection_source
            .map(|source| source.as_str().to_owned())
            .unwrap_or_default(),
        tamper_active: state.tamper_active(),
        expected_wall_ms: tick.expected_wall_ms,
        persisted_json: state.to_json().unwrap_or_default(),
    }
}

#[uniffi::export]
pub fn clock_integrity_trusted_wall_ms(persisted_state_json: String, boottime_ms: i64) -> i64 {
    ClockIntegrityState::from_json(&persisted_state_json)
        .unwrap_or_else(|_| ClockIntegrityState::new(PersistedClockIntegrity::default()))
        .trusted_wall_ms(boottime_ms)
}

#[uniffi::export]
pub fn clock_integrity_set_otp_override(persisted_state_json: String, active: bool) -> String {
    let mut state = ClockIntegrityState::from_json(&persisted_state_json)
        .unwrap_or_else(|_| ClockIntegrityState::new(PersistedClockIntegrity::default()));
    state.set_otp_override(active);
    state.to_json().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with_baseline(wall: i64, boottime: i64) -> ClockIntegrityState {
        ClockIntegrityState::new(PersistedClockIntegrity {
            baseline_wall_ms: wall,
            baseline_boottime_ms: boottime,
            ..PersistedClockIntegrity::default()
        })
    }

    #[test]
    fn matched_suspend_advance_does_not_tamper() {
        let mut state = state_with_baseline(1_000_000, 10_000);
        assert_eq!(
            state.tick(4_600_000, 3_610_000, None).status,
            TickStatus::Ok
        );
        assert!(!state.tamper_active());
    }

    #[test]
    fn wall_jump_without_boottime_is_tamper() {
        let mut state = state_with_baseline(1_000_000, 10_000);
        assert_eq!(
            state.tick(1_400_000, 10_500, None).status,
            TickStatus::TamperDetected
        );
    }

    #[test]
    fn ntp_mismatch_triggers_tamper() {
        let mut state = state_with_baseline(1_000_000, 10_000);
        let tick = state.tick(1_000_000, 10_500, Some(1_400_000));
        assert_eq!(tick.status, TickStatus::TamperDetected);
        assert_eq!(tick.detection_source, Some(DetectionSource::Ntp));
    }

    #[test]
    fn hysteresis_requires_two_passes_to_clear() {
        let mut state = ClockIntegrityState::new(PersistedClockIntegrity {
            baseline_wall_ms: 1_000_000,
            baseline_boottime_ms: 10_000,
            tamper_active: true,
            ..PersistedClockIntegrity::default()
        });
        assert_eq!(
            state.tick(1_000_500, 10_500, Some(1_000_500)).status,
            TickStatus::Ok
        );
        assert_eq!(
            state.tick(1_001_000, 11_000, Some(1_001_000)).status,
            TickStatus::TamperCleared
        );
    }

    #[test]
    fn reboot_still_flags_ntp_mismatch() {
        let mut state = state_with_baseline(1_000_000, 3_610_000);
        let tick = state.tick(1_003_700_000, 60_000, Some(1_004_100_000));
        assert_eq!(tick.status, TickStatus::TamperDetected);
        assert_eq!(tick.detection_source, Some(DetectionSource::Ntp));
    }

    #[test]
    fn reboot_rebaselines_without_tamper() {
        let mut state = state_with_baseline(1_000_000, 3_610_000);
        let tick = state.tick(1_003_700_000, 60_000, None);
        assert_eq!(tick.status, TickStatus::Ok);
        assert!(!state.tamper_active());
    }

    #[test]
    fn reboot_clears_false_positive_tamper() {
        let mut state = ClockIntegrityState::new(PersistedClockIntegrity {
            baseline_wall_ms: 1_000_000,
            baseline_boottime_ms: 3_610_000,
            tamper_active: true,
            ..PersistedClockIntegrity::default()
        });
        let tick = state.tick(1_003_700_000, 60_000, None);
        assert_eq!(tick.status, TickStatus::TamperCleared);
        assert!(!state.tamper_active());
    }

    #[test]
    fn otp_override_clears_active_tamper() {
        let mut state = ClockIntegrityState::new(PersistedClockIntegrity {
            tamper_active: true,
            ..PersistedClockIntegrity::default()
        });
        state.set_otp_override(true);
        assert!(!state.tamper_active());
    }

    #[test]
    fn filetime_conversion_matches_known_value() {
        let unix_ms = 1_704_067_200_000_i64;
        let filetime = u64::try_from(unix_ms).unwrap() * 10_000 + FILETIME_EPOCH_DIFF_100NS;
        let bytes = filetime.to_le_bytes();
        let low = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let high = u32::from_le_bytes(bytes[4..].try_into().unwrap());
        assert_eq!(filetime_to_unix_ms(low, high), unix_ms);
    }
}
