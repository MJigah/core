#![allow(dead_code)]
use txwatch_config::{AlertRule, Network, RuleConfig, WatchedContract};

/// Build a `WatchedContract` fixture with sensible test defaults.
///
/// Centralizes the literal so that new fields on `WatchedContract` only need
/// to be updated here (and in `WatchedContract::test_default`).
pub fn contract(webhook_url: &str, rules: Vec<AlertRule>) -> WatchedContract {
    WatchedContract {
        label: "Integration Test Contract".into(),
        contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
        network: Network::Testnet,
        rules: rules
            .into_iter()
            .map(|r| RuleConfig {
                rule: r,
                cooldown_seconds: None,
            })
            .collect(),
        webhook_url: Some(webhook_url.to_string()),
        webhook_secret: None,
        poll_interval_seconds: None,
        enabled: true,
        soroban_rpc_url: None,
        horizon_base_url_override: None,
        webhook_format: Default::default(),
        webhook_headers: Default::default(),
        webhook_routing_key: None,
        webhooks: Vec::new(),
        batch_alerts: false,
    }
}

pub fn tx_page(hash: &str, paging_token: &str, successful: bool) -> serde_json::Value {
    serde_json::json!({
        "_embedded": {
            "records": [{
                "hash":         hash,
                "created_at":   "2024-06-01T10:00:00Z",
                "successful":   successful,
                "paging_token": paging_token,
                "fee_charged":  "100",
                "envelope_xdr": null,
                "result_xdr":   null
            }]
        }
    })
}

/// Base64-encode `bytes` (standard alphabet, with padding).
pub fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// The XDR-encoded `ScVal` base64 value of a `Sym`, as Horizon returns it:
/// a 4-byte big-endian discriminant (15 == SCV_SYMBOL), a 4-byte big-endian
/// length, then the UTF-8 bytes padded to a 4-byte boundary.
pub fn sym_param(name: &str) -> String {
    let mut raw = vec![0, 0, 0, 15];
    raw.extend_from_slice(&(name.len() as u32).to_be_bytes());
    raw.extend_from_slice(name.as_bytes());
    while raw.len() % 4 != 0 {
        raw.push(0);
    }
    b64(&raw)
}

/// A realistic `invoke_host_function` operation.
///
/// `function` is the *host function type*, not the contract function name —
/// that is what Horizon actually returns, and matching against it is the bug
/// fixed in issue #3. The name is the `Sym` parameter.
pub fn invoke_op(function_name: &str) -> serde_json::Value {
    serde_json::json!({
        "type":     "invoke_host_function",
        "function": "HostFunctionTypeHostFunctionTypeInvokeContract",
        "parameters": [
            { "type": "Address", "value": "AAAAEgAAAAEJIX5C6S3X6ftDOw+T3MtGCdZN6Xv2zEfpPmTF42f8og==" },
            { "type": "Sym",     "value": sym_param(function_name) }
        ]
    })
}

pub fn ops_page(function_name: &str) -> serde_json::Value {
    serde_json::json!({ "_embedded": { "records": [invoke_op(function_name)] } })
}

pub fn payment_ops_page(amount_str: &str) -> serde_json::Value {
    serde_json::json!({
        "_embedded": {
            "records": [{
                "type":       "payment",
                "asset_type": "native",
                "amount": amount_str
            }]
        }
    })
}

pub fn empty_page() -> serde_json::Value {
    serde_json::json!({ "_embedded": { "records": [] } })
}

pub fn tx_page_3(hash1: &str, hash2: &str, hash3: &str) -> serde_json::Value {
    serde_json::json!({
        "_embedded": {
            "records": [
                {
                    "hash": hash1, "created_at": "2024-06-01T10:00:00Z",
                    "successful": true, "paging_token": "1",
                    "fee_charged": "100", "envelope_xdr": null, "result_xdr": null
                },
                {
                    "hash": hash2, "created_at": "2024-06-01T10:01:00Z",
                    "successful": true, "paging_token": "2",
                    "fee_charged": "100", "envelope_xdr": null, "result_xdr": null
                },
                {
                    "hash": hash3, "created_at": "2024-06-01T10:02:00Z",
                    "successful": true, "paging_token": "3",
                    "fee_charged": "100", "envelope_xdr": null, "result_xdr": null
                }
            ]
        }
    })
}

/// Build a `WatchedContract` fixture with an explicit contract id.
///
/// Used by the crash-restart harness, which needs several distinct contracts
/// sharing one state file.
pub fn contract_with_id(
    contract_id: &str,
    webhook_url: &str,
    rules: Vec<AlertRule>,
) -> WatchedContract {
    let mut c = contract(webhook_url, rules);
    c.contract_id = contract_id.to_string();
    c
}

/// Build a multi-contract config that all share a single state file.
///
/// `contracts` is a list of `(contract_id, webhook_url, rules)` tuples. The
/// returned config points every contract at the same `state_file`, which is
/// what the crash-restart test needs in order to verify that cursors and
/// tracker state survive a hard kill.
pub fn multi_contract_config(
    contracts: Vec<(&str, &str, Vec<AlertRule>)>,
    state_file: &std::path::Path,
) -> txwatch_config::Config {
    let mut cfg = txwatch_config::Config::default();
    cfg.contracts = contracts
        .into_iter()
        .map(|(id, url, rules)| contract_with_id(id, url, rules))
        .collect();
    cfg.state_file = Some(state_file.to_path_buf());
    cfg
}

/// Spawn `run_with_reload` on a dedicated runtime and return the join handle.
///
/// The caller is expected to `abort()` the returned handle (or drop the
/// runtime) to simulate a crash without a graceful shutdown signal.
pub fn spawn_poller(
    cfg: txwatch_config::Config,
) -> (
    tokio::runtime::Runtime,
    tokio::task::JoinHandle<()>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build test runtime");
    let handle = rt.spawn(async move {
        // Errors are expected when the task is aborted mid-flight.
        let _ = txwatch_poller::run_with_reload(cfg).await;
    });
    (rt, handle)
}

/// Abort a poller spawned by [`spawn_poller`] without any shutdown signal,
/// then wait for the runtime to tear down so the state file is flushed as it
/// would be on a crash.
pub fn crash_poller(
    rt: tokio::runtime::Runtime,
    handle: tokio::task::JoinHandle<()>,
) {
    handle.abort();
    // Dropping the runtime blocks until all tasks are cancelled.
    drop(rt);
}

/// A page of transactions with caller-supplied `(hash, paging_token)` pairs.
///
/// Lets a test assert that every transaction is delivered exactly once across
/// a restart by collecting the hashes it observes.
pub fn tx_page_hashes(entries: &[(&str, &str)]) -> serde_json::Value {
    let records: Vec<serde_json::Value> = entries
        .iter()
        .map(|(hash, token)| {
            serde_json::json!({
                "hash":         hash,
                "created_at":   "2024-06-01T10:00:00Z",
                "successful":   true,
                "paging_token": token,
                "fee_charged":  "100",
                "envelope_xdr": null,
                "result_xdr":   null
            })
        })
        .collect();
    serde_json::json!({ "_embedded": { "records": records } })
}
