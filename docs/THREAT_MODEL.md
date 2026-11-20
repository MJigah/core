# TxWatch Threat Model

## 1. System Overview & Architecture

TxWatch is a security monitoring daemon for Soroban smart contracts on the Stellar network. It continuously polls the Stellar Horizon API for newly ingested transactions, enriches transaction data with Soroban invocation details and payments, evaluates user-defined alert rules against enriched transactions, and dispatches webhook payloads signed via HMAC-SHA256 to external monitoring endpoints (e.g. alerting pipelines, Slack, Discord, custom webhooks).

```
+-------------------------------------------------------------------------------+
|                                TxWatch Daemon                                 |
|                                                                               |
|  +--------------------+        +--------------------+                         |
|  |   txwatch-cli      | -----> |   txwatch-config   |                         |
|  +--------------------+        +--------------------+                         |
|            |                             |                                    |
|            v                             v                                    |
|  +--------------------+        +--------------------+                         |
|  |   txwatch-poller   | <----> |   txwatch-rules    |                         |
|  +--------------------+        +--------------------+                         |
|            |                                                                  |
|            v                                                                  |
|  +--------------------+                                                       |
|  |  txwatch-notifier  |                                                       |
|  +--------------------+                                                       |
+------------|------------------------------------------------------------------+
             |
             v (HTTP POST / HMAC-SHA256)
     [ External Webhook Receiver ]
```

---

## 2. Assets & Data Flow

| Asset | Sensitivity | Invariants & Security Objectives |
| :--- | :--- | :--- |
| **Webhook Secrets (`webhook_secret`)** | Critical / Confidential | Must never be logged in plaintext, must not be leaked via HTTP headers (`X-TxWatch-Secret` deprecated/isolated), must not be exposed over plain unencrypted HTTP. |
| **Webhook Destination URLs** | Medium / Confidential | Often embed sensitive tokens (e.g. Slack webhook URLs); must be redacted in public logs and stdout. |
| **Cursor State (`cursor_file`)** | High / Integrity | Must accurately track the latest processed transaction paging token; writes must be atomic to prevent rollback/replay or skipped transactions. |
| **Alert Rules Configuration** | High / Integrity | Must not allow integer overflow, arbitrary injection, or unvalidated host/path traversal. |
| **Alert Notification Payloads** | Medium / Authenticity | Must be verifiable by the receiver via HMAC-SHA256 signature to guarantee payload integrity and authenticity. |
| **User-Supplied Templates (minijinja)** | High / Integrity | Templates render untrusted on-chain data (memos, event data); rendering must not allow code execution, filesystem/network access, or unbounded resource consumption. |
| **`include` Globs** | High / Integrity | Include patterns must not allow loading arbitrary files outside the intended template directory (path traversal / glob expansion abuse). |
| **mTLS Private Keys** | Critical / Confidential | Keys read from disk for client authentication must never be logged, embedded in error messages, or exposed via metrics; file permissions must be restrictive. |
| **Metrics Endpoint (`/metrics`)** | Medium / Confidential | Unauthenticated listener must not disclose secrets, webhook URLs, private keys, or high-cardinality attacker-controlled labels. |
| **Persistence Files (`cursor_file`, state)** | High / Integrity | Tampered persistence files must not be able to inject arbitrary Horizon query parameters or redirect polling to attacker-controlled endpoints. |
| **Horizon Pagination Links** | High / Integrity | `next`/`prev` links supplied by Horizon must not be followed blindly to arbitrary hosts or schemes (SSRF / credential leakage). |

---

## 3. Trust Boundaries & Threat Actors

### Trust Boundaries
1. **Daemon Boundary (Local Process vs External Network)**: Horizon API nodes (untrusted remote input) and Webhook receivers (untrusted remote endpoints).
2. **Configuration Boundary**: File system permissions on TOML configuration and cursor files; environment variables.
3. **Internal Crate Interfaces**: Separation of validation (`txwatch-config`), detection (`txwatch-rules`), poller coordination (`txwatch-poller`), and transport delivery (`txwatch-notifier`).

### Threat Actors
- **Malicious Horizon Node / MITM**: Supplies malformed JSON, forged transactions, recursive pagination loops, or excessive 429 rate limit responses.
- **Malicious Webhook Receiver / Adversary**: Attempts Server-Side Request Forgery (SSRF) against internal metadata or loopback services, slowloris DoS (hanging connections), or replay attacks using intercepted signatures.
- **Local Low-Privilege Attacker**: Attempts path traversal via `cursor_file`, reading plaintext secrets from log aggregators, or process termination mid-flight.

---

## 4. STRIDE Threat Analysis

| Threat Category | Potential Attack Vector | Component | Mitigation & Defense |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Forged alerts sent to receiver; replaying old alert payloads | `txwatch-notifier` | HMAC-SHA256 signature over payload body; inclusion of timestamp in signed claims. |
| **Tampering** | Interrupted cursor writes resulting in corrupted JSON cursor state | `txwatch-poller` | Atomic file write via `.tmp` file swap with `fs::rename`. |
| **Repudiation** | Dropped webhook alerts without persistence or tracing | `txwatch-poller`, `txwatch-notifier` | Structured tracing, error logging, and retry backoff mechanics. |
| **Information Disclosure** | Webhook secrets leaked in logs or error messages; cleartext transmission | `txwatch-config`, `txwatch-notifier` | Redaction of tokens in logs; enforcement of HTTPS when secrets are configured. |
| **Denial of Service** | Slow or unreachable receiver blocking Horizon polling loop; integer overflow | `txwatch-poller`, `txwatch-rules` | Asynchronous decoupled webhook delivery; checked arithmetic on thresholds (`checked_mul`). |
| **Elevation of Privilege** | Arbitrary file overwrite via unsanitized cursor file paths | `txwatch-config` | Strict path handling, atomic file creation, and deny-unknown-fields deserialization. |
| **Spoofing** | Attacker-controlled Horizon pagination links redirect polling to a malicious host (SSRF / forged data source) | `txwatch-poller` | Pagination links are validated against the configured Horizon base URL and scheme before being followed; only relative paths or same-origin absolute URLs are accepted. See [#488](https://github.com/txwatch/txwatch/issues/488). |
| **Tampering** | Tampered persistence/cursor files inject arbitrary Horizon query parameters (e.g. overriding `cursor`, `order`, `limit`, or endpoint path) | `txwatch-poller` | Persisted state is schema-validated on load (deny-unknown-fields), query parameters are constructed from typed config rather than persisted strings, and cursor values are validated as opaque paging tokens. See [#488](https://github.com/txwatch/txwatch/issues/488). |
| **Tampering** | User-supplied minijinja templates rendering untrusted on-chain data (memos, event data) attempt to escape the sandbox or abuse template features | `txwatch-rules` | minijinja is configured without filesystem/network loaders, with strict undefined handling, output/recursion limits, and auto-escaping; rendered on-chain data is treated as data, never as template source. See [#488](https://github.com/txwatch/txwatch/issues/488). |
| **Tampering** | `include` globs load arbitrary files from disk (path traversal, symlink escape, glob expansion outside template root) | `txwatch-config` | Include patterns are resolved relative to a configured template root, canonicalized, and rejected if they escape that root; symlinks are not followed outside the root and glob expansion is bounded. See [#488](https://github.com/txwatch/txwatch/issues/488). |
| **Information Disclosure** | mTLS private keys read from disk leaked via logs, error messages, or metrics | `txwatch-config`, `txwatch-notifier` | Keys are loaded into memory only, never formatted/logged (redacted `Debug`), errors reference the path but not contents, and file permission checks warn on world-readable keys. See [#488](https://github.com/txwatch/txwatch/issues/488). |
| **Information Disclosure** | Unauthenticated `/metrics` listener exposes secrets, webhook URLs, private keys, or attacker-controlled high-cardinality labels | `txwatch-cli` | Metrics are bound to a configurable (default loopback) address, expose only fixed-name counters/gauges, never include secrets or raw URLs, and label values are drawn from a bounded set. See [#488](https://github.com/txwatch/txwatch/issues/488). |

---

## 5. Crate-by-Crate Security Threats & Mitigations

### 1. `txwatch-config`
- **Threat**: Malformed contract addresses or absurd numeric thresholds (e.g. `threshold_xlm` > 1,000,000,000) leading to integer overflow or dead-looping rules.
- **Mitigation**: Bounds checking (`MAX_LARGE_TRANSFER_THRESHOLD_XLM`), Soroban symbol character set validation (`[a-zA-Z0-9_]`), and URL scheme validation.
- **Threat (includes)**: `include` globs resolve to arbitrary files outside the template root (path traversal, symlink escape, unbounded glob expansion).
- **Mitigation (includes)**: Includes are resolved relative to a configured template root, canonicalized, and rejected if they escape it; symlinks outside the root are refused and glob expansion is bounded. See [#488](https://github.com/txwatch/txwatch/issues/488).
- **Threat (mTLS keys)**: Private keys read from disk for mTLS are exposed via logs, error messages, or overly permissive file modes.
- **Mitigation (mTLS keys)**: Keys are loaded into memory only, redacted in `Debug`/logs, never included in error text, and world-readable key files produce a warning. See [#488](https://github.com/txwatch/txwatch/issues/488).

### 2. `txwatch-rules`
- **Threat**: Integer overflow when converting whole XLM to stroops (`10_000_000` multiplier); case sensitivity mismatches when matching function names.
- **Mitigation**: Safe checked arithmetic (`checked_mul`), normalization of admin function symbols to lowercase, and rigorous payload type checking.
- **Threat (templates)**: User-supplied minijinja templates render untrusted on-chain data (memos, event data) and may attempt sandbox escape, resource exhaustion, or output injection.
- **Mitigation (templates)**: minijinja is configured without filesystem/network loaders, with strict undefined handling, output/recursion limits, and auto-escaping; on-chain data is passed as data and never re-parsed as template source. See [#488](https://github.com/txwatch/txwatch/issues/488).

### 3. `txwatch-notifier`
- **Threat**: Exposure of shared secrets; slow receivers exhausting connection pools; infinite retries on unrecoverable HTTP 4xx client errors.
- **Mitigation**: Hard retry limits (`MAX_RETRIES`), exponential backoff with sleep interruption on shutdown, and immediate failure on non-retryable 4xx responses.

### 4. `txwatch-poller`
- **Threat**: Head-of-line blocking where inline await on webhook delivery stalls contract polling; cursor desynchronization causing missing alerts.
- **Mitigation**: Concurrent JoinSet polling per contract; decoupled webhook execution; atomic cursor updates before enrichment.
- **Threat (persistence)**: Tampered persistence/cursor files inject arbitrary Horizon query parameters or redirect polling.
- **Mitigation (persistence)**: Persisted state is schema-validated on load (deny-unknown-fields), query parameters are built from typed config rather than persisted strings, and cursor values are validated as opaque paging tokens. See [#488](https://github.com/txwatch/txwatch/issues/488).
- **Threat (pagination)**: Horizon-supplied `next`/`prev` pagination links are followed blindly to arbitrary hosts or schemes (SSRF, credential leakage, forged data source).
- **Mitigation (pagination)**: Pagination links are validated against the configured Horizon base URL and scheme before being followed; only relative paths or same-origin absolute URLs are accepted. See [#488](https://github.com/txwatch/txwatch/issues/488).

### 5. `txwatch-cli`
- **Threat**: Signal termination leaving in-flight deliveries broken; argument injection in subcommand handlers.
- **Mitigation**: Graceful shutdown token broadcast (`watch::Receiver<bool>`); clap-based strict type parsing.
- **Threat (metrics)**: The unauthenticated `/metrics` listener exposes secrets, webhook URLs, private keys, or attacker-controlled high-cardinality labels.
- **Mitigation (metrics)**: Metrics bind to a configurable (default loopback) address, expose only fixed-name counters/gauges, never include secrets or raw URLs, and label values come from a bounded set. See [#488](https://github.com/txwatch/txwatch/issues/488).

---

## 6. Verification & Executable Attack Tests

Executable attack tests are located across all crate test suites:
- `crates/config/tests/attack_tests.rs`: Malicious config injection, threshold overflow, and invalid contract ID validation.
- `crates/rules/tests/attack_tests.rs`: Arithmetic overflow exploitation, case-spoofing in symbols, and malformed XDR transactions.
- `crates/notifier/tests/attack_tests.rs`: Replay attacks, retry exhaustion attacks, and secret leakage prevention.
- `crates/poller/tests/attack_tests.rs`: Malicious Horizon pagination DoS, 429 flood resilience, and atomic cursor recovery.
- `crates/cli/tests/attack_tests.rs`: Signal interruption resilience and config path validation.
- `crates/rules/tests/attack_tests.rs` (templates): Malicious minijinja templates rendering untrusted memos/event data, sandbox escape attempts, and resource-exhaustion inputs. See [#488](https://github.com/txwatch/txwatch/issues/488).
- `crates/config/tests/attack_tests.rs` (includes): `include` glob path traversal, symlink escape outside the template root, and unbounded glob expansion. See [#488](https://github.com/txwatch/txwatch/issues/488).
- `crates/config/tests/attack_tests.rs` (mTLS keys): Private key leakage via logs/errors and overly permissive key file modes. See [#488](https://github.com/txwatch/txwatch/issues/488).
- `crates/cli/tests/attack_tests.rs` (metrics): `/metrics` disclosure of secrets/URLs and high-cardinality label injection. See [#488](https://github.com/txwatch/txwatch/issues/488).
- `crates/poller/tests/attack_tests.rs` (persistence & pagination): Tampered persistence files injecting Horizon query parameters and malicious pagination links pointing off-origin. See [#488](https://github.com/txwatch/txwatch/issues/488).
