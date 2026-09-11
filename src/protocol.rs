//! WebSocket protocol types shared by every Guardian agent.
//!
//! Field names and `#[serde(tag = "type")]` discriminators are part of the v1
//! wire format and must stay byte-compatible with the Flask server.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Local account advertised during `hello` (Linux uid or Windows RID).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LinuxUser {
    pub username: String,
    pub uid: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AgentConfig {
    pub server_url: String,
    pub system_id: Option<String>,
    pub registration_token: Option<String>,
    pub agent_token: Option<String>,
    #[serde(default)]
    pub github_repo: Option<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: "ws://localhost:5000/ws".to_string(),
            system_id: None,
            registration_token: None,
            agent_token: None,
            github_repo: None,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum ServerMessage {
    #[serde(rename = "pairing_status")]
    PairingStatus { status: String },
    #[serde(rename = "pairing_approved")]
    PairingApproved { token: String },
    #[serde(rename = "challenge")]
    Challenge { challenge: String },
    #[serde(rename = "auth_result")]
    AuthResult {
        success: bool,
        message: String,
        #[serde(default)]
        update_required: bool,
        #[serde(default)]
        update_available: bool,
        #[serde(default)]
        target_version: Option<String>,
        #[serde(default)]
        github_repo: Option<String>,
        #[serde(default)]
        download_url: Option<String>,
        #[serde(default)]
        checksum_url: Option<String>,
        #[serde(default)]
        apk_url: Option<String>,
        #[serde(default)]
        signature_checksum: Option<String>,
    },
    #[serde(rename = "command_request")]
    CommandRequest {
        correlation_id: String,
        action: String,
        username: String,
        args: serde_json::Value,
    },
    #[serde(rename = "policy_sync_hint")]
    PolicySyncHint { reason: Option<String> },
    #[serde(rename = "installed_apps_report_ack")]
    InstalledAppsReportAck {
        #[serde(default)]
        report_id: Option<String>,
        success: bool,
        #[serde(default)]
        apps_upserted: Option<u64>,
        #[serde(default)]
        apps_removed: Option<u64>,
        #[serde(default)]
        apps_total: Option<u64>,
        #[serde(default)]
        pending: bool,
        #[serde(default)]
        message: Option<String>,
    },
    #[serde(rename = "screenshot_report_ack")]
    ScreenshotReportAck {
        #[serde(default)]
        screenshot_id: Option<String>,
        success: bool,
        #[serde(default)]
        duplicate: bool,
        #[serde(default)]
        message: Option<String>,
    },
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum ClientMessage {
    #[serde(rename = "hello")]
    Hello {
        system_id: String,
        system_hostname: Option<String>,
        registration_token: Option<String>,
        agent_version: String,
        linux_users: Option<Vec<LinuxUser>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        paired: Option<bool>,
        platform: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        agent_arch: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        hardware_oem: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        hardware_oem_model: Option<String>,
    },
    #[serde(rename = "register")]
    Register {
        system_id: String,
        signature: String,
    },
    #[serde(rename = "command_response")]
    CommandResponse {
        correlation_id: String,
        success: bool,
        message: String,
        data: serde_json::Value,
    },
    #[serde(rename = "alert_event")]
    AlertEvent {
        event_type: String,
        occurred_at: String,
        linux_username: Option<String>,
        details: serde_json::Value,
    },
    #[serde(rename = "policy_sync_check")]
    PolicySyncCheck {
        source_revisions: HashMap<String, String>,
    },
    #[serde(rename = "credential_escrow")]
    CredentialEscrow {
        credential_type: String,
        rotation_id: String,
        occurred_at: String,
        password: String,
    },
}

/// In-process alert forwarded from OS monitors onto the WebSocket writer.
#[derive(Debug, Clone)]
pub struct AppAlert {
    pub event_type: String,
    pub linux_username: String,
    pub payload: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::{ClientMessage, ServerMessage};

    #[test]
    fn hello_uses_v1_type_tag() {
        let encoded = serde_json::to_value(ClientMessage::Hello {
            system_id: "dev".into(),
            system_hostname: Some("box".into()),
            registration_token: None,
            agent_version: "v1.0.0".into(),
            linux_users: None,
            paired: Some(true),
            platform: "linux".into(),
            agent_arch: Some("x86_64".into()),
            hardware_oem: None,
            hardware_oem_model: None,
        })
        .unwrap();
        assert_eq!(encoded["type"], "hello");
        assert_eq!(encoded["agent_version"], "v1.0.0");
        assert_eq!(encoded["paired"], true);
    }

    #[test]
    fn installed_apps_report_ack_deserializes() {
        let success_ack = r#"{"type":"installed_apps_report_ack","report_id":"abc","success":true,"apps_upserted":12,"apps_removed":1,"apps_total":12,"pending":false}"#;
        match serde_json::from_str::<ServerMessage>(success_ack).unwrap() {
            ServerMessage::InstalledAppsReportAck {
                report_id,
                success,
                apps_upserted,
                apps_removed,
                apps_total,
                pending,
                message,
            } => {
                assert_eq!(report_id.as_deref(), Some("abc"));
                assert!(success);
                assert_eq!(apps_upserted, Some(12));
                assert_eq!(apps_removed, Some(1));
                assert_eq!(apps_total, Some(12));
                assert!(!pending);
                assert!(message.is_none());
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }
}
