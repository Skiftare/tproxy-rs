//! tproxy-rs binary entry point.
use std::path::PathBuf;
use std::str::FromStr;

use clap::{Parser, Subcommand};
use tproxy_rs::config::{Backend, Config};
use tproxy_rs::mass::MassConfig;
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
    /// Public hostname (overrides config + env TPROXY_HOSTNAME).
    #[arg(long)]
    hostname: Option<String>,
    /// Web-proxy secret(s), repeatable (overrides secret_hex/secret_hexes).
    #[arg(long, action = clap::ArgAction::Append)]
    secret: Vec<String>,
    /// Mass-production subcommand.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Stamp out many proxy sites from one YAML file.
    #[command(name = "mass")]
    Mass {
        /// Path to mass YAML.
        yaml: PathBuf,
        /// Output directory for rendered configs/secrets (default: ./mass).
        #[arg(long, default_value = "mass")]
        out: PathBuf,
        /// Print generated secrets to stdout (default: yes unless --out to CI).
        #[arg(long)]
        print_secrets: bool,
        /// Dry-run: materialize the plan and print it, but write nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Mass-production mode: render per-site configs + secrets from YAML.
    if let Some(Command::Mass { yaml, out, print_secrets, dry_run }) = cli.command {
        return run_mass(&yaml, &out, print_secrets, dry_run);
    }

    let mut cfg: Config = Config::default();
    if cli.config.exists() {
        let raw = std::fs::read_to_string(&cli.config)?;
        cfg = serde_json::from_str(&raw)?;
    }
    cfg.apply_env();
    if let Some(port) = cli.port {
        cfg.listen = format!("0.0.0.0:{port}");
    }
    if let Some(h) = cli.hostname {
        if !h.is_empty() { cfg.public_hostname = h; }
    }
    if !cli.secret.is_empty() {
        // CLI secrets go into backends (multi-secret); first also as primary.
        if cfg.secret_hex.is_empty() && !cli.secret[0].is_empty() {
            cfg.secret_hex = cli.secret[0].clone();
        }
        for s in &cli.secret {
            if !s.is_empty() {
                cfg.backends.push(Backend {
                    secret_hex: s.clone(),
                    mtproxy_addr: cfg.mtproxy_addr.clone(),
                });
            }
        }
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

/// Mass-production: parse YAML, materialize, render configs+secrets.
fn run_mass(
    path: &std::path::Path,
    out: &std::path::Path,
    print_secrets: bool,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let base = path.parent().unwrap_or(std::path::Path::new("."));
    let cfg = MassConfig::load(path)?;
    let plan = cfg.materialize(base)?;

    println!("==========================================================");
    println!(
        "  MASS-PRODUCED WEB PROXIES ({}) {}",
        plan.sites.len(),
        if dry_run { "[DRY-RUN: nothing written]" } else { "" }
    );
    println!("  isolation: {}", plan.isolation);
    println!("==========================================================");
    println!("  Host                                    Backends  Secrets");
    for site in &plan.sites {
        let secrets = format!(
            "{} key{} ({})",
            site.secrets.len(),
            if site.secrets.len() == 1 { "" } else { "s" },
            if site.secrets.len() <= 3 || print_secrets {
                site.secrets.join(" , ")
            } else {
                "see secrets.txt".into()
            }
        );
        println!(
            "  {:<40} {:<9} {}",
            site.domain,
            site.backends.len(),
            secrets
        );
    }
    if !dry_run {
        let summary = plan.export(out)?;
        println!("==========================================================");
        println!("  configs rendered to {}", out.display());
        println!("  secrets file: {}/secrets.txt (chmod 600)", out.display());
        let _ = summary;
    } else {
        println!("==========================================================");
        println!("  dry-run: no files written. Re-run without --dry-run to render.");
    }
    Ok(())
}
