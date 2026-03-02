mod ebpf;
mod errors;
mod events;
mod networks;

use crate::ebpf::EbpfAgent;
use crate::error::Result;
use crate::events::Event;
use env_logger::Env;
use log::{error, info, warn};
use std::env;
use tokio::sync::mpsc;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    info!("🛡️  Starting Secure eBPF Agent v{}", env!("CARGO_PKG_VERSION"));

    let config = Config::from_env()?;
    config.log();

    let (tx, mut rx) = mpsc::channel::<Event>(config.channel_buffer_size);

    let mut agent = match EbpfAgent::new(config.backend_url.clone(), tx).await {
        Ok(agent) => {
            info!("eBPF agent initialized successfully");
            agent
        }
        Err(e) => {
            error!("Failed to initialize eBPF agent: {}", e);
            return Err(e);
        }
    };

    let event_handler = tokio::spawn(async move {
        let mut event_count = 0u64;
        
        while let Some(event) = rx.recv().await {
            event_count += 1;
            
            if event_count % 100 == 0 {
                info!("Processed {} events", event_count);
            }

            match event.get_event_type() {
                events::EventType::FileOpen => {
                    debug!(
                        "File access: PID={} opened {}",
                        event.pid,
                        event.get_filename_lossy()
                    );
                }
                events::EventType::NetworkConnect => {
                    debug!(
                        "Network: PID={} connected to {}:{}",
                        event.pid,
                        event.get_dest_ip(),
                        event.dest_port
                    );
                }
                events::EventType::Unknown => {
                    warn!("Unknown event type from PID={}", event.pid);
                }
            }
        }
        
        info!("Event handler shutting down. Total events processed: {}", event_count);
    });

    info!("Starting eBPF monitoring... Press Ctrl+C to stop");

    tokio::select! {
        result = agent.run() => {
            if let Err(e) = result {
                error!("eBPF agent error: {}", e);
            }
        }
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    info!("Shutting down gracefully...");
    event_handler.abort();
    
    info!("Agent stopped");
    Ok(())
}

fn init_logging() {
    env_logger::Builder::from_env(
        Env::default().default_filter_or("info,aya=warn,reqwest=warn")
    )
    .format_timestamp_secs()
    .init();
}

struct Config {
    backend_url: String,
    channel_buffer_size: usize,
    log_level: String,
}

impl Config {
    fn from_env() -> Result<Self> {
        let backend_url = env::var("BACKEND_URL")
            .unwrap_or_else(|_| "http://localhost:8000".to_string());

        let channel_buffer_size = env::var("CHANNEL_BUFFER_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let log_level = env::var("RUST_LOG")
            .unwrap_or_else(|_| "info".to_string());

        Ok(Self {
            backend_url,
            channel_buffer_size,
            log_level,
        })
    }

    fn log(&self) {
        info!("Configuration:");
        info!("  Backend URL: {}", self.backend_url);
        info!("  Channel Buffer Size: {}", self.channel_buffer_size);
        info!("  Log Level: {}", self.log_level);
    }
}