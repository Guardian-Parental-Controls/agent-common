//! Config file location and persistence shared by desktop agents.

use std::fs;
use std::path::Path;

use uuid::Uuid;

use crate::protocol::AgentConfig;

pub fn get_config_path() -> String {
    #[cfg(target_os = "windows")]
    {
        let primary_dir = r"C:\ProgramData\Guardian";
        let primary_path = format!("{primary_dir}\\config.json");
        let fallback_path = "config.json";

        if Path::new(&primary_path).exists() {
            primary_path
        } else if Path::new(fallback_path).exists() {
            fallback_path.to_string()
        } else if fs::create_dir_all(primary_dir).is_ok() {
            primary_path
        } else {
            fallback_path.to_string()
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let primary_dir = "/etc/guardian-agent";
        let primary_path = format!("{primary_dir}/config.json");
        let fallback_path = "config.json";

        if Path::new(&primary_path).exists() {
            primary_path
        } else if Path::new(fallback_path).exists() {
            fallback_path.to_string()
        } else if fs::create_dir_all(primary_dir).is_ok() {
            primary_path
        } else {
            fallback_path.to_string()
        }
    }
}

pub fn load_or_create_config() -> AgentConfig {
    let config_path = get_config_path();
    println!("Loading config from: {config_path}");

    let mut config = fs::read_to_string(&config_path)
        .ok()
        .and_then(|data| serde_json::from_str::<AgentConfig>(&data).ok())
        .unwrap_or_default();

    if config
        .system_id
        .as_ref()
        .is_none_or(|value| value.trim().is_empty())
    {
        let new_uuid = Uuid::new_v4().to_string();
        println!("------------------------------------------------------------");
        println!("GENERATE NEW HOST UUID: {new_uuid}");
        println!("PLEASE REGISTER THIS HOST UUID IN THE SERVER WEB UI PANEL!");
        println!("------------------------------------------------------------");
        config.system_id = Some(new_uuid);
        save_config(&config);
    }

    config
}

pub fn save_config(config: &AgentConfig) {
    let config_path = get_config_path();
    match serde_json::to_string_pretty(config) {
        Ok(serialized) => {
            if let Err(error) = fs::write(&config_path, serialized) {
                eprintln!("Warning: Failed to save config to {config_path}: {error}");
            }
        }
        Err(error) => eprintln!("Warning: Failed to serialize config: {error}"),
    }
}

pub fn clear_agent_enrollment() -> Result<(), String> {
    let mut config = load_or_create_config();
    config.agent_token = None;
    let serialized = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("Failed to serialize config: {error}"))?;
    fs::write(get_config_path(), serialized)
        .map_err(|error| format!("Failed to write config: {error}"))?;
    Ok(())
}

pub fn get_system_hostname() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("COMPUTERNAME")
            .ok()
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            let trimmed = hostname.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        if let Ok(hostname_file) = fs::read_to_string("/etc/hostname") {
            let trimmed = hostname_file.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        std::process::Command::new("hostname")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|hostname| hostname.trim().to_string())
            .filter(|hostname| !hostname.is_empty())
    }
}

pub fn agent_version_string() -> String {
    let version = option_env!("GUARDIAN_AGENT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}
