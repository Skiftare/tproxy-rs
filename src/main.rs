//! tproxy-rs binary entry point.
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;
use tproxy_rs::config::Config;
use tproxy_rs::server::{router, AppState};

#[derive(Parser, Debug)]
#[command(name = "tproxy-rs", about = "Telegram WEB proxy relay (Rust)")]
struct Cli {
    /// Path to config JSON.
    #[arg(short, long, default_value = "config.json")]
    config: PathBuf,
    /// Port to listen on (overrides config.listen).
    #[arg(long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let raw = std::fs::read_to_string(&cli.config)?;
    let mut cfg: Config = serde_json::from_str(&raw)?;
    cfg.apply_env();
    if let Some(port) = cli.port {
        cfg.listen = format!("127.0.0.1:{port}");
    }
    let listen_addr = cfg.listen.clone();
    let st = AppState::new(cfg);
    let app = router(st);
    let addr = std::net::SocketAddr::from_str(&listen_addr)
        .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error>)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("tproxy-rs listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
