//! State persistence for cursors, cooldowns, and NoActivity states.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use txwatch_config::AppConfig;
use txwatch_rules::{CooldownTracker, NoActivityState};

/// Persisted state document containing cursors, cooldowns, and NoActivity states.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct StateDocument {
    #[serde(default)]
    pub cursors: HashMap<String, String>,
    #[serde(default)]
    pub cooldowns: HashMap<String, CooldownTracker>,
    /// NoActivity states keyed by contract name, then by stable rule identity.
    #[serde(default)]
    pub no_activity: HashMap<String, HashMap<String, NoActivityState>>,
}

impl StateDocument {
    pub fn from_cursors(cursors: HashMap<String, String>) -> Self {
        Self {
            cursors,
            cooldowns: HashMap::new(),
            no_activity: HashMap::new(),
        }
    }

    pub fn from_parts(
        cursors: HashMap<String, String>,
        cooldowns: HashMap<String, CooldownTracker>,
        no_activity: HashMap<String, HashMap<String, NoActivityState>>,
    ) -> Self {
        Self {
            cursors,
            cooldowns,
            no_activity,
        }
    }
}

pub struct StateLock(Option<PathBuf>);

impl Drop for StateLock {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

pub fn acquire_state_lock(cursor_file: Option<&str>) -> Result<StateLock> {
    let Some(path_str) = cursor_file else {
        return Ok(StateLock(None));
    };
    let lock_path = PathBuf::from(format!("{}.lock", path_str));
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .with_context(|| format!("failed to acquire lock '{}'", lock_path.display()))?;
    Ok(StateLock(Some(lock_path)))
}

pub fn load_state(cfg: &AppConfig) -> StateDocument {
    let path = cfg.state_file.as_deref().or(cfg.cursor_file.as_deref());
    let Some(path) = path else {
        return StateDocument::default();
    };
    let Ok(content) = fs::read_to_string(path) else {
        return StateDocument::default();
    };
    let doc = if let Ok(doc) = serde_json::from_str::<StateDocument>(&content) {
        doc
    } else if let Ok(cursors) = serde_json::from_str::<HashMap<String, String>>(&content) {
        StateDocument::from_cursors(cursors)
    } else {
        StateDocument::default()
    };
    prune_state(cfg, doc)
}

/// Prune persisted tracker entries whose rule no longer exists in the config.
pub fn prune_state(cfg: &AppConfig, mut doc: StateDocument) -> StateDocument {
    let mut valid_contracts: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut valid_rule_hashes: std::collections::HashSet<String> = std::collections::HashSet::new();
    for contract in &cfg.contracts {
        valid_contracts.insert(contract.name.clone());
        for rule in &contract.rules {
            valid_rule_hashes.insert(txwatch_rules::rule_identity(rule));
        }
    }

    doc.cooldowns.retain(|key, _| valid_contracts.contains(key));

    doc.no_activity.retain(|contract, states| {
        if !valid_contracts.contains(contract) {
            return false;
        }
        states.retain(|hash, _| valid_rule_hashes.contains(hash));
        !states.is_empty()
    });

    doc
}

pub fn save_state(cfg: &AppConfig, doc: &StateDocument) -> Result<()> {
    let path = cfg.state_file.as_deref().or(cfg.cursor_file.as_deref());
    let Some(path) = path else {
        return Ok(());
    };
    write_state_blocking(Path::new(path), doc)
}

pub fn write_state_blocking(path: &Path, doc: &StateDocument) -> Result<()> {
    let raw = serde_json::to_string_pretty(doc).context("failed to serialize state document")?;
    let tmp = path.with_extension("tmp");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&tmp, raw.as_bytes())
        .with_context(|| format!("failed to write state file '{}'", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename state file '{}'", path.display()))?;
    Ok(())
}

/// Merge a single [`StateUpdate`] into the state document already on disk and
/// write the result atomically.
///
/// This is the synchronous counterpart of the background writer task: it lets
/// callers (notably crash-survival tests) persist an update immediately without
/// waiting for the writer task to drain its channel. The on-disk document is
/// re-read first so unrelated keys are preserved.
pub fn write_state_update_blocking(path: &Path, update: &StateUpdate) -> Result<()> {
    let mut doc = if let Ok(content) = fs::read_to_string(path) {
        serde_json::from_str::<StateDocument>(&content).unwrap_or_default()
    } else {
        StateDocument::default()
    };
    doc.cursors
        .insert(update.cursor_key.clone(), update.cursor.clone());
    doc.cooldowns
        .insert(update.cursor_key.clone(), update.cooldowns.clone());
    doc.no_activity
        .insert(update.cursor_key.clone(), update.no_activity.clone());
    write_state_blocking(path, &doc)
}

#[derive(Debug, Clone)]
pub struct StateUpdate {
    pub cursor_key: String,
    pub cursor: String,
    pub cooldowns: CooldownTracker,
    pub no_activity: HashMap<String, NoActivityState>,
}

#[derive(Clone)]
pub struct StateHandle {
    sender: Option<tokio::sync::mpsc::UnboundedSender<StateUpdate>>,
}

impl StateHandle {
    pub fn send(&self, update: StateUpdate) {
        if let Some(s) = &self.sender {
            let _ = s.send(update);
        }
    }

    pub async fn flush(&self) {
        tokio::task::yield_now().await;
    }
}

pub struct StateWriter {
    handle: StateHandle,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl StateWriter {
    pub fn handle(&self) -> StateHandle {
        self.handle.clone()
    }

    pub async fn shutdown(mut self) {
        self.handle.sender.take();
        if let Some(join) = self.join_handle.take() {
            let _ = join.await;
        }
    }
}

pub fn spawn_state_writer(cursor_file: Option<&str>) -> StateWriter {
    let Some(path_str) = cursor_file else {
        return StateWriter {
            handle: StateHandle { sender: None },
            join_handle: None,
        };
    };
    let path = PathBuf::from(path_str);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<StateUpdate>();
    let join = tokio::spawn(async move {
        let mut current_doc = StateDocument::default();
        while let Some(update) = rx.recv().await {
            current_doc.cursors.insert(update.cursor_key.clone(), update.cursor);
            current_doc.cooldowns.insert(update.cursor_key.clone(), update.cooldowns);
            current_doc.no_activity.insert(update.cursor_key, update.no_activity);
            let _ = write_state_blocking(&path, &current_doc);
        }
    });
    StateWriter {
        handle: StateHandle { sender: Some(tx) },
        join_handle: Some(join),
    }
}
