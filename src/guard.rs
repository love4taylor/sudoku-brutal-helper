use crate::command::{NativeRunner, client_prefix};
use anyhow::{Context, Result, bail};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StateEntry {
    ip: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct StateDocument {
    version: u8,
    entries: Vec<StateEntry>,
}

pub struct Guard {
    runner: NativeRunner,
    state_path: PathBuf,
    max_ips: usize,
    rate_mbps: u64,
    listen_port: u16,
    entries: Vec<StateEntry>,
    stale_entries: Vec<IpAddr>,
    pending_disconnect: HashSet<IpAddr>,
    state_dirty: bool,
}

impl Guard {
    pub fn new(
        runner: NativeRunner,
        state_path: PathBuf,
        max_ips: usize,
        rate_mbps: u64,
        listen_port: u16,
    ) -> Self {
        Self {
            runner,
            state_path,
            max_ips,
            rate_mbps,
            listen_port,
            entries: Vec::new(),
            stale_entries: Vec::new(),
            pending_disconnect: HashSet::new(),
            state_dirty: false,
        }
    }

    pub fn scan_clients(&self) -> Result<Vec<IpAddr>> {
        self.runner.scan_clients(self.listen_port)
    }

    pub fn load_state(&mut self) -> Result<()> {
        if !self.state_path.exists() {
            return Ok(());
        }
        let contents = fs::read_to_string(&self.state_path)
            .with_context(|| format!("failed to read state file {}", self.state_path.display()))?;
        let document: StateDocument = serde_json::from_str(&contents)
            .with_context(|| format!("state file {} is invalid", self.state_path.display()))?;
        if document.version != 1 {
            bail!("state file {} has an unsupported version", self.state_path.display());
        }

        let mut seen = HashSet::new();
        for entry in document.entries {
            match entry.ip.parse::<IpAddr>() {
                Ok(ip) if seen.insert(ip) => self.entries.push(StateEntry { ip: ip.to_string() }),
                _ => self.state_dirty = true,
            }
        }
        if self.entries.len() > self.max_ips {
            let remove_count = self.entries.len() - self.max_ips;
            self.stale_entries = self
                .entries
                .drain(..remove_count)
                .filter_map(|entry| entry.ip.parse().ok())
                .collect();
            self.state_dirty = true;
        }
        Ok(())
    }

    pub fn reconcile(&mut self) -> Result<()> {
        for ip in self.stale_entries.drain(..) {
            if !self.runner.delete(ip)? {
                bail!("failed to remove stale rule {} beyond max_ips", client_prefix(ip));
            }
        }
        for entry in &self.entries {
            let ip = entry.ip.parse().context("state file contains an invalid IP")?;
            self.runner.add(ip)?;
        }
        if self.state_dirty {
            self.save_state()?;
            self.state_dirty = false;
        }
        if !self.entries.is_empty() {
            info!("restored {} client Brutal rules", self.entries.len());
        }
        Ok(())
    }

    pub fn needs_attention(&self, ip: IpAddr) -> bool {
        self.pending_disconnect.contains(&ip)
    }

    pub fn observe(&mut self, ip: IpAddr, force_disconnect: bool) -> Result<()> {
        let key = ip.to_string();
        if let Some(index) = self.entries.iter().position(|entry| entry.ip == key) {
            if index + 1 != self.entries.len() {
                let original = self.entries.clone();
                let entry = self.entries.remove(index);
                self.entries.push(entry);
                if let Err(error) = self.save_state() {
                    self.entries = original;
                    return Err(error);
                }
            }
            if force_disconnect || self.pending_disconnect.contains(&ip) {
                self.disconnect_or_retry(ip)?;
            }
            return Ok(());
        }

        let original = self.entries.clone();
        self.runner.add(ip)?;
        let mut evicted = None;
        if self.entries.len() >= self.max_ips {
            let old_ip: IpAddr = self.entries[0].ip.parse().context("state file contains an invalid IP")?;
            if !self.runner.delete(old_ip)? {
                let _ = self.runner.delete(ip);
                bail!("failed to evict oldest client rule {}", client_prefix(old_ip));
            }
            self.entries.remove(0);
            self.pending_disconnect.remove(&old_ip);
            evicted = Some(old_ip);
        }
        self.entries.push(StateEntry { ip: key });

        if let Err(error) = self.save_state() {
            self.entries = original;
            let _ = self.runner.delete(ip);
            if let Some(old_ip) = evicted
                && let Err(restore_error) = self.runner.add(old_ip)
            {
                warn!("failed to roll back Brutal rule {}: {restore_error:#}", client_prefix(old_ip));
            }
            return Err(error);
        }

        let disconnected = self.disconnect_or_retry(ip)?;
        let mut message = format!(
            "added {} ({} Mbps, {}/{})",
            client_prefix(ip),
            self.rate_mbps,
            self.entries.len(),
            self.max_ips
        );
        if let Some(old_ip) = evicted {
            message.push_str(&format!(", evicted {}", client_prefix(old_ip)));
        }
        if disconnected {
            message.push_str(", existing connections destroyed");
        } else {
            message.push_str(", existing connections will be retried on the next scan");
        }
        info!("{message}");
        Ok(())
    }

    fn disconnect_or_retry(&mut self, ip: IpAddr) -> Result<bool> {
        let disconnected = self.runner.disconnect(ip, self.listen_port)?;
        if disconnected {
            self.pending_disconnect.remove(&ip);
        } else {
            self.pending_disconnect.insert(ip);
        }
        Ok(disconnected)
    }

    fn save_state(&self) -> Result<()> {
        if self.runner.is_dry_run() {
            return Ok(());
        }
        let parent = self.state_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create state directory {}", parent.display()))?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let temp_path = parent.join(format!(
            ".{}.{}.{}.tmp",
            self.state_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("state"),
            std::process::id(),
            nonce
        ));
        let document = serde_json::to_vec_pretty(&StateDocument {
            version: 1,
            entries: self.entries.clone(),
        })?;
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp_path)
                .with_context(|| format!("failed to create temporary state file {}", temp_path.display()))?;
            file.write_all(&document)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&temp_path, &self.state_path)
                .with_context(|| format!("failed to replace state file {}", self.state_path.display()))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;

    #[test]
    fn keeps_recent_clients_with_dry_run_runner() {
        let settings = Settings {
            max_ips: 2,
            ..Settings::default()
        };
        let runner = NativeRunner::new(&settings, true);
        let mut guard = Guard::new(runner, settings.state_file, 2, 1000, 8443);
        guard.observe("192.0.2.1".parse().unwrap(), false).unwrap();
        guard.observe("192.0.2.2".parse().unwrap(), false).unwrap();
        guard.observe("192.0.2.1".parse().unwrap(), false).unwrap();
        guard.observe("192.0.2.3".parse().unwrap(), false).unwrap();
        let addresses: Vec<&str> = guard.entries.iter().map(|entry| entry.ip.as_str()).collect();
        assert_eq!(addresses, ["192.0.2.1", "192.0.2.3"]);
    }
}
