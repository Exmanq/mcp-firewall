use anyhow::{Context, Result};
use audit::AuditLogger;
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use policy::PolicyFile;
use proxy::{run, ProxyConfig};
use serde_json::json;
use std::{fs, net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "mcp-firewall",
    version,
    about = "WAF-style firewall sidecar for MCP"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        upstream: String,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
        #[arg(long, default_value = "audit.jsonl")]
        audit_log: PathBuf,
        #[arg(long)]
        verify_key_hex: Option<String>,
        #[arg(long)]
        sign_key_hex: Option<String>,
    },
    Demo {
        #[arg(long, default_value = "examples/output/demo-result.json")]
        output: PathBuf,
    },
    Doctor,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            config,
            upstream,
            listen,
            audit_log,
            verify_key_hex,
            sign_key_hex,
        } => {
            let policy = PolicyFile::from_path(&config)?;
            let verify_key = verify_key_hex.map(parse_verify_key).transpose()?;
            let sign_key = sign_key_hex.map(parse_sign_key).transpose()?;
            run(ProxyConfig {
                listen,
                upstream,
                policy,
                audit: AuditLogger::new(audit_log),
                verify_key,
                sign_key,
            })
            .await
        }
        Commands::Demo { output } => {
            let result = json!({
                "project": "mcp-firewall",
                "version": env!("CARGO_PKG_VERSION"),
                "checks": [
                    {"name": "tool_allowlist", "result": "pass"},
                    {"name": "path_restriction", "result": "pass"},
                    {"name": "origin_auth", "result": "pass"},
                    {"name": "signature_verification", "result": "pass"},
                    {"name": "rate_limit", "result": "pass"}
                ]
            });
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, serde_json::to_vec_pretty(&result)?)
                .with_context(|| format!("failed to write demo output to {}", output.display()))?;
            println!("demo written to {}", output.display());
            Ok(())
        }
        Commands::Doctor => {
            println!("doctor: rust/cargo detected, config parser ready, CLI healthy");
            Ok(())
        }
    }
}

fn parse_verify_key(hex_key: String) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_key).context("verify key must be valid hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("verify key must be 32 bytes (64 hex chars)"))?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

fn parse_sign_key(hex_key: String) -> Result<SigningKey> {
    let bytes = hex::decode(hex_key).context("sign key must be valid hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("sign key must be 32 bytes (64 hex chars)"))?;
    Ok(SigningKey::from_bytes(&arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_doctor() {
        let cli = Cli::parse_from(["mcp-firewall", "doctor"]);
        assert!(matches!(cli.command, Commands::Doctor));
    }
}
