//! Screen-time and allowed-hours evaluation.

use std::collections::HashMap;

#[derive(uniffi::Record, Clone, Debug)]
pub struct HourSlot {
    pub start_min: i32,
    pub end_min: i32,
    pub uacc: i32,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct UserTimeState {
    pub enabled: bool,
    pub time_left_day: i32,
    pub allowed_days: Vec<i32>,
}

#[uniffi::export]
pub fn check_screentime_allowed(
    state: UserTimeState,
    current_hour: i32,
    current_minute: i32,
    day_of_week: i32,
    allowed_hours: HashMap<String, HashMap<String, HourSlot>>,
) -> bool {
    if !state.enabled || state.time_left_day <= 0 || !state.allowed_days.contains(&day_of_week) {
        return false;
    }

    let day_key = day_of_week.to_string();
    if let Some(day_hours) = allowed_hours.get(&day_key) {
        let hour_key = current_hour.to_string();
        if let Some(slot) = day_hours.get(&hour_key) {
            return current_minute >= slot.start_min
                && current_minute < slot.end_min
                && slot.uacc == 0;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{HourSlot, UserTimeState, check_screentime_allowed};

    fn enabled_state() -> UserTimeState {
        UserTimeState {
            enabled: true,
            time_left_day: 60,
            allowed_days: vec![1],
        }
    }

    #[test]
    fn rejects_disabled_or_exhausted_users() {
        let mut state = enabled_state();
        state.time_left_day = 0;
        assert!(!check_screentime_allowed(state, 9, 0, 1, HashMap::new()));
    }

    #[test]
    fn applies_the_matching_hour_slot() {
        let hours = HashMap::from([(
            "1".to_owned(),
            HashMap::from([(
                "9".to_owned(),
                HourSlot {
                    start_min: 15,
                    end_min: 45,
                    uacc: 0,
                },
            )]),
        )]);
        assert!(check_screentime_allowed(enabled_state(), 9, 30, 1, hours));
    }
}
