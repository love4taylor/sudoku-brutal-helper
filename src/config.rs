use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/sudoku-brutal-helper.json";

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub sudoku_config: PathBuf,
    pub listen_port: Option<u16>,
    pub rate_mbps: u64,
    pub max_ips: usize,
    pub poll_interval_ms: u64,
    pub state_file: PathBuf,
    pub operation_timeout_seconds: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            sudoku_config: PathBuf::from("/etc/sudoku/config.json"),
            listen_port: None,
            rate_mbps: 1000,
            max_ips: 20,
            poll_interval_ms: 200,
            state_file: PathBuf::from("/var/lib/sudoku-brutal-helper/state.json"),
            operation_timeout_seconds: 15,
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self> {
        let settings = if path.exists() {
            let contents = fs::read_to_string(path)
                .with_context(|| format!("failed to read configuration file {}", path.display()))?;
            serde_json::from_str(&contents)
                .with_context(|| format!("configuration file {} is invalid", path.display()))?
        } else {
            Self::default()
        };
        settings.validate()
    }

    fn validate(self) -> Result<Self> {
        for (name, path) in [
            ("sudoku_config", &self.sudoku_config),
            ("state_file", &self.state_file),
        ] {
            if path.as_os_str().is_empty() {
                bail!("{name} cannot be empty");
            }
        }
        if self.listen_port == Some(0) {
            bail!("listen_port must be in the range 1..=65535");
        }
        if self.rate_mbps == 0 {
            bail!("rate_mbps must be a positive integer");
        }
        if self.max_ips == 0 {
            bail!("max_ips must be a positive integer");
        }
        if !(20..=60_000).contains(&self.poll_interval_ms) {
            bail!("poll_interval_ms must be in the range 20..=60000");
        }
        if self.operation_timeout_seconds == 0 {
            bail!("operation_timeout_seconds must be a positive integer");
        }
        Ok(self)
    }

    pub fn resolve_listen_port(&self) -> Result<u16> {
        if let Some(port) = self.listen_port {
            return Ok(port);
        }
        let contents = fs::read_to_string(&self.sudoku_config).with_context(|| {
            format!(
                "failed to read Sudoku configuration file {}",
                self.sudoku_config.display()
            )
        })?;
        parse_sudoku_port(&contents, &self.sudoku_config)
    }
}

#[derive(Debug, Deserialize)]
struct SudokuConfig {
    mode: Option<String>,
    transport: Option<String>,
    local_port: Option<u16>,
}

fn parse_sudoku_port(contents: &str, path: &Path) -> Result<u16> {
    let config: SudokuConfig = serde_json::from_str(contents)
        .with_context(|| format!("Sudoku configuration file {} is invalid", path.display()))?;
    if config
        .mode
        .as_deref()
        .is_some_and(|mode| mode.trim().eq_ignore_ascii_case("client"))
    {
        bail!("{} is a client configuration; it cannot provide server inbound connections", path.display());
    }
    if config.transport.as_deref().is_some_and(|transport| {
        let transport = transport.trim();
        !transport.is_empty() && !transport.eq_ignore_ascii_case("tcp")
    }) {
        bail!("Sudoku transport is not TCP; TCP Brutal cannot be applied");
    }
    match config.local_port {
        Some(port @ 1..=u16::MAX) => Ok(port),
        _ => bail!("Sudoku configuration is missing a valid local_port"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_server_port() {
        let port = parse_sudoku_port(
            r#"{"mode":"server","transport":"tcp","local_port":8443}"#,
            Path::new("config.json"),
        )
        .unwrap();
        assert_eq!(port, 8443);
    }

    #[test]
    fn rejects_client_and_non_tcp_configs() {
        assert!(
            parse_sudoku_port(
                r#"{"mode":"client","local_port":1080}"#,
                Path::new("config.json")
            )
            .is_err()
        );
        assert!(
            parse_sudoku_port(
                r#"{"mode":"server","transport":"udp","local_port":8080}"#,
                Path::new("config.json")
            )
            .is_err()
        );
    }
}
