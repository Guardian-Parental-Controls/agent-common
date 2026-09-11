//! Shared WebSocket reconnect / handshake loop.
//!
//! OS crates implement [`AgentRuntime`] for enforcement; this module owns the
//! wire handshake, HMAC registration, command dispatch, and backoff.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use uuid::Uuid;

use crate::auth::generate_auth_signature;
use crate::config::{
    agent_version_string, get_system_hostname, load_or_create_config, save_config,
};
use crate::protocol::{AgentConfig, ClientMessage, LinuxUser, ServerMessage};

pub type ActiveClientTx = Arc<Mutex<Option<mpsc::UnboundedSender<ClientMessage>>>>;

#[derive(Debug, Clone)]
pub struct CommandOutcome {
    pub success: bool,
    pub message: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct UpdateOffer {
    pub required: bool,
    pub target_version: Option<String>,
    pub download_url: Option<String>,
    pub checksum_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HardwareInfo {
    pub oem: String,
    pub model: Option<String>,
}

/// Platform-specific work invoked from the shared reconnect loop.
pub trait AgentRuntime: Send + Sync + 'static {
    fn list_users(&self) -> Vec<LinuxUser>;
    fn hardware(&self) -> HardwareInfo;
    fn startup_details(&self, hostname: Option<&str>) -> serde_json::Value;

    fn handle_command(
        &self,
        action: &str,
        username: &str,
        args: &serde_json::Value,
    ) -> impl Future<Output = CommandOutcome> + Send;

    fn apply_update(&self, offer: UpdateOffer) -> impl Future<Output = Result<(), String>> + Send;

    fn after_authenticate(
        &self,
        client_tx: &mpsc::UnboundedSender<ClientMessage>,
    ) -> impl Future<Output = ()> + Send;

    fn spawn_authenticated_tasks(
        &self,
        client_tx: mpsc::UnboundedSender<ClientMessage>,
        inventory_tx: mpsc::UnboundedSender<String>,
        shutdown: watch::Receiver<bool>,
        policy_sync_rx: mpsc::UnboundedReceiver<()>,
        screenshot_trigger_tx: mpsc::UnboundedSender<Option<String>>,
        screenshot_trigger_rx: mpsc::UnboundedReceiver<Option<String>>,
    ) -> Vec<JoinHandle<()>>;

    fn push_inventory(&self, inventory_tx: &mpsc::UnboundedSender<String>, username: &str);

    fn after_disconnect(&self) {}
}

pub fn build_alert_message(
    event_type: &str,
    linux_username: Option<String>,
    mut details: serde_json::Value,
) -> ClientMessage {
    let occurred_at = if let Some(obj) = details.as_object_mut() {
        obj.remove("_occurred_at")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(current_timestamp)
    } else {
        current_timestamp()
    };

    ClientMessage::AlertEvent {
        event_type: event_type.to_string(),
        occurred_at,
        linux_username,
        details: if details.is_object() {
            details
        } else {
            serde_json::json!({})
        },
    }
}

fn current_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

async fn maybe_apply_update<R: AgentRuntime>(runtime: &R, offer: UpdateOffer, label: &str) {
    if offer.target_version.is_none() {
        return;
    }
    println!("{label}: {:?}. Starting updater...", offer.target_version);
    match runtime.apply_update(offer).await {
        Ok(()) => {
            println!("Successfully updated binary! Exiting to allow service restart.");
            std::process::exit(0);
        }
        Err(error) => eprintln!("Auto-update failed: {error}"),
    }
}

pub async fn run_reconnect_loop<R: AgentRuntime>(
    runtime: Arc<R>,
    active_client_tx: ActiveClientTx,
) {
    loop {
        let mut device_unenrolled = false;
        let config = load_or_create_config();
        let server_url = config.server_url.clone();
        let system_id = config
            .system_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let agent_token = config.agent_token.clone();
        let registration_token = config.registration_token.clone();
        let system_hostname = get_system_hostname();

        println!("Connecting to server: {server_url}");

        match connect_async(&server_url).await {
            Ok((mut ws_stream, _)) => {
                println!("WebSocket connected! Starting handshake...");
                let hardware = runtime.hardware();
                let hello_msg = ClientMessage::Hello {
                    system_id: system_id.clone(),
                    system_hostname: system_hostname.clone(),
                    registration_token,
                    agent_version: agent_version_string(),
                    linux_users: Some(runtime.list_users()),
                    paired: Some(agent_token.is_some()),
                    platform: std::env::consts::OS.to_string(),
                    agent_arch: Some(std::env::consts::ARCH.to_string()),
                    hardware_oem: Some(hardware.oem),
                    hardware_oem_model: hardware.model,
                };
                if send_json(&mut ws_stream, &hello_msg).await.is_err() {
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
                println!("Sent hello message to server.");

                let authenticated = match complete_handshake(
                    &mut ws_stream,
                    &config,
                    &system_id,
                    agent_token.as_deref(),
                    runtime.as_ref(),
                )
                .await
                {
                    HandshakeResult::Authenticated => true,
                    HandshakeResult::Reconnect => false,
                    HandshakeResult::Failed => {
                        sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };

                if !authenticated {
                    println!("Handshake did not complete; reconnecting.");
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }

                let (mut ws_write, mut ws_read) = ws_stream.split();
                let (client_tx, mut client_rx) = mpsc::unbounded_channel::<ClientMessage>();
                let (inventory_tx, mut inventory_rx) = mpsc::unbounded_channel::<String>();
                {
                    let mut guard = active_client_tx.lock().unwrap();
                    *guard = Some(client_tx.clone());
                }
                let writer_handle = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            maybe_message = client_rx.recv() => {
                                let Some(message) = maybe_message else { break };
                                let Ok(serialized) = serde_json::to_string(&message) else { continue };
                                if ws_write.send(Message::Text(serialized.into())).await.is_err() {
                                    break;
                                }
                            }
                            maybe_inventory = inventory_rx.recv() => {
                                let Some(message) = maybe_inventory else { break };
                                if ws_write.send(Message::Text(message.into())).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });

                let (shutdown_tx, shutdown_rx) = watch::channel(false);
                let (policy_sync_tx, policy_sync_rx) = mpsc::unbounded_channel::<()>();
                let (screenshot_trigger_tx, screenshot_trigger_rx) =
                    mpsc::unbounded_channel::<Option<String>>();
                let mut session_handles = runtime.spawn_authenticated_tasks(
                    client_tx.clone(),
                    inventory_tx.clone(),
                    shutdown_rx,
                    policy_sync_rx,
                    screenshot_trigger_tx.clone(),
                    screenshot_trigger_rx,
                );

                let _ = client_tx.send(build_alert_message(
                    "system_startup",
                    None,
                    runtime.startup_details(system_hostname.as_deref()),
                ));
                runtime.after_authenticate(&client_tx).await;

                while let Some(msg_result) = ws_read.next().await {
                    match msg_result {
                        Ok(Message::Text(text)) => {
                            match serde_json::from_str::<ServerMessage>(&text) {
                                Ok(ServerMessage::CommandRequest {
                                    correlation_id,
                                    action,
                                    username,
                                    args,
                                }) => {
                                    let outcome =
                                        runtime.handle_command(&action, &username, &args).await;
                                    let response = ClientMessage::CommandResponse {
                                        correlation_id,
                                        success: outcome.success,
                                        message: outcome.message,
                                        data: outcome.data,
                                    };
                                    if client_tx.send(response).is_err() {
                                        break;
                                    }
                                    if action == "refresh_installed_apps" && outcome.success {
                                        runtime.push_inventory(&inventory_tx, &username);
                                    }
                                    if action == "capture_screenshot" && outcome.success {
                                        let target = args
                                            .get("linux_username")
                                            .and_then(|value| value.as_str())
                                            .map(ToOwned::to_owned)
                                            .or_else(|| {
                                                (!username.trim().is_empty())
                                                    .then(|| username.clone())
                                            });
                                        let _ = screenshot_trigger_tx.send(target);
                                    }
                                    if action == "unenroll" && outcome.success {
                                        device_unenrolled = true;
                                        let _ = shutdown_tx.send(true);
                                        break;
                                    }
                                }
                                Ok(ServerMessage::PolicySyncHint { reason }) => {
                                    println!(
                                        "Received policy sync hint{}",
                                        reason
                                            .as_deref()
                                            .map(|value| format!(": {value}"))
                                            .unwrap_or_default()
                                    );
                                    let _ = policy_sync_tx.send(());
                                }
                                Ok(ServerMessage::InstalledAppsReportAck {
                                    success,
                                    message,
                                    ..
                                }) => {
                                    if !success {
                                        eprintln!(
                                            "Installed apps report rejected: {}",
                                            message.as_deref().unwrap_or("unknown error")
                                        );
                                    }
                                }
                                Ok(ServerMessage::ScreenshotReportAck {
                                    success,
                                    message,
                                    duplicate,
                                    ..
                                }) => {
                                    if !success {
                                        eprintln!(
                                            "Screenshot report rejected: {}",
                                            message.as_deref().unwrap_or("unknown error")
                                        );
                                    } else if duplicate {
                                        eprintln!("Screenshot report ignored as duplicate");
                                    }
                                }
                                Ok(other) => {
                                    eprintln!(
                                        "Ignoring unexpected server message after authentication: {other:?}"
                                    );
                                }
                                Err(error) => eprintln!("Failed to parse server message: {error}"),
                            }
                        }
                        Ok(Message::Close(_)) => {
                            println!("Connection closed by server.");
                            break;
                        }
                        Err(error) => {
                            eprintln!("WebSocket stream error: {error}");
                            break;
                        }
                        _ => {}
                    }
                }

                {
                    let mut guard = active_client_tx.lock().unwrap();
                    *guard = None;
                }
                runtime.after_disconnect();
                let _ = shutdown_tx.send(true);
                drop(client_tx);
                drop(policy_sync_tx);
                for handle in session_handles.drain(..) {
                    let _ = handle.await;
                }
                let _ = writer_handle.await;
            }
            Err(error) => eprintln!("Connection failed: {error}. Retrying..."),
        }

        if device_unenrolled {
            println!("Device unenrolled; stopping agent reconnect loop.");
            return;
        }

        println!("Reconnecting in 5 seconds...");
        sleep(Duration::from_secs(5)).await;
    }
}

enum HandshakeResult {
    Authenticated,
    Reconnect,
    Failed,
}

async fn complete_handshake<S, R>(
    ws_stream: &mut S,
    config: &AgentConfig,
    system_id: &str,
    agent_token: Option<&str>,
    runtime: &R,
) -> HandshakeResult
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + SinkExt<Message>
        + Unpin,
    R: AgentRuntime,
{
    while let Some(msg_result) = ws_stream.next().await {
        match msg_result {
            Ok(Message::Text(text)) => match serde_json::from_str::<ServerMessage>(&text) {
                Ok(ServerMessage::PairingStatus { status }) => {
                    println!("Received pairing status: {status}");
                }
                Ok(ServerMessage::PairingApproved { token }) => {
                    println!("Pairing approved! Received secure token.");
                    let mut updated = config.clone();
                    updated.agent_token = Some(token);
                    save_config(&updated);
                    println!(
                        "Successfully saved agent token to config! Reconnecting in 2 seconds..."
                    );
                    return HandshakeResult::Reconnect;
                }
                Ok(ServerMessage::Challenge { challenge }) => {
                    let Some(token) = agent_token else {
                        eprintln!(
                            "Received authentication challenge but no agent token is configured!"
                        );
                        return HandshakeResult::Failed;
                    };
                    let register_msg = ClientMessage::Register {
                        system_id: system_id.to_string(),
                        signature: generate_auth_signature(
                            token.to_string(),
                            challenge,
                            system_id.to_string(),
                        ),
                    };
                    if send_json(ws_stream, &register_msg).await.is_err() {
                        return HandshakeResult::Failed;
                    }
                }
                Ok(ServerMessage::AuthResult {
                    success,
                    message,
                    update_required,
                    update_available,
                    target_version,
                    download_url,
                    checksum_url,
                    ..
                }) => {
                    println!("Handshake result: success = {success}, message = {message}");
                    if success {
                        if update_available {
                            maybe_apply_update(
                                runtime,
                                UpdateOffer {
                                    required: false,
                                    target_version,
                                    download_url,
                                    checksum_url,
                                },
                                "Optional update available",
                            )
                            .await;
                        }
                        return HandshakeResult::Authenticated;
                    }
                    eprintln!("Authentication failed: {message}");
                    if update_required && update_available {
                        maybe_apply_update(
                            runtime,
                            UpdateOffer {
                                required: true,
                                target_version,
                                download_url,
                                checksum_url,
                            },
                            "Version update required",
                        )
                        .await;
                    }
                    return HandshakeResult::Failed;
                }
                Ok(_) => {}
                Err(error) => eprintln!("Failed to parse server message during handshake: {error}"),
            },
            Ok(Message::Close(_)) => return HandshakeResult::Failed,
            Err(_) => return HandshakeResult::Failed,
            _ => {}
        }
    }
    HandshakeResult::Failed
}

async fn send_json<S>(ws_stream: &mut S, message: &ClientMessage) -> Result<(), ()>
where
    S: SinkExt<Message> + Unpin,
{
    let serialized = serde_json::to_string(message).map_err(|_| ())?;
    ws_stream
        .send(Message::Text(serialized.into()))
        .await
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::build_alert_message;
    use crate::protocol::ClientMessage;

    #[test]
    fn alert_messages_use_expected_shape() {
        let message = build_alert_message(
            "system_startup",
            Some("alice".to_string()),
            serde_json::json!({"source": "test"}),
        );
        match message {
            ClientMessage::AlertEvent {
                event_type,
                linux_username,
                details,
                occurred_at,
            } => {
                assert_eq!(event_type, "system_startup");
                assert_eq!(linux_username.as_deref(), Some("alice"));
                assert!(occurred_at.ends_with('Z'));
                assert_eq!(details["source"], "test");
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }
}
