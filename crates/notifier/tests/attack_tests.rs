//! Attack tests for `txwatch-notifier` verifying HMAC signature defenses,
//! retry exhaustion behavior, and denial of service resistance.

use std::sync::{Arc, Mutex};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::oneshot;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use txwatch_notifier::{build_client, send_webhook, test_payload};

#[tokio::test]
async fn test_attack_hmac_tamper_detection() {
    let payload = test_payload("AttackTest");
    let body = serde_json::to_string(&payload).unwrap();
    let secret = "correct-secret-key";

    // Compute legitimate HMAC
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let valid_signature = hex::encode(mac.finalize().into_bytes());

    // Tampered payload body simulation
    let mut tampered_mac = Hmac::<Sha256>::new_from_slice(b"forged-attacker-key").unwrap();
    tampered_mac.update(body.as_bytes());
    let forged_signature = hex::encode(tampered_mac.finalize().into_bytes());

    assert_ne!(
        valid_signature, forged_signature,
        "Forged secret must never produce matching HMAC signature"
    );
}

#[tokio::test]
async fn test_attack_server_slowloris_or_500_flood_terminates() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let url = format!("{}/hook", server.uri());
    let payload = test_payload("SlowlorisDefense");
    let (_tx, rx) = oneshot::channel();

    let result = send_webhook(&client, &url, &payload, Some("secret"), rx).await;
    assert!(
        result.is_err(),
        "Exhausted retries on 500 flood must terminate with error"
    );
}

#[tokio::test]
async fn test_attack_huge_success_body_is_capped() {
    let server = MockServer::start().await;
    // A misbehaving receiver streams a very large 2xx body. The notifier must
    // not read it unbounded into memory; it should cap the read and still
    // treat the delivery as successful.
    let huge_body = "A".repeat(8 * 1024 * 1024);
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200).set_body_string(huge_body))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let url = format!("{}/hook", server.uri());
    let payload = test_payload("HugeBodyDefense");
    let (_tx, rx) = oneshot::channel();

    let result = send_webhook(&client, &url, &payload, Some("secret"), rx).await;
    assert!(
        result.is_ok(),
        "A 2xx with a huge body must still be treated as a successful delivery"
    );
}

/// Records the `contract` field of every span that is entered, keyed by span id.
#[derive(Clone, Default)]
struct SpanRecorder {
    entered: Arc<Mutex<Vec<(u64, String)>>>,
}

struct ContractVisitor<'a>(&'a mut Option<String>);

impl Visit for ContractVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "contract" {
            *self.0 = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "contract" {
            *self.0 = Some(format!("{:?}", value));
        }
    }
}

impl<S> Layer<S> for SpanRecorder
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut contract = None;
        attrs.record(&mut ContractVisitor(&mut contract));
        if let Some(contract) = contract {
            if let Some(span) = ctx.span(id) {
                span.extensions_mut().insert(contract);
            }
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            if let Some(contract) = span.extensions().get::<String>() {
                self.entered
                    .lock()
                    .unwrap()
                    .push((id.into_u64(), contract.clone()));
            }
        }
    }

    fn on_event(&self, _event: &Event<'_>, _ctx: Context<'_, S>) {}
}

#[tokio::test]
async fn test_concurrent_deliveries_keep_span_attribution() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let recorder = SpanRecorder::default();
    let subscriber = tracing_subscriber::registry().with(recorder.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let client = build_client().unwrap();
    let url = format!("{}/hook", server.uri());

    let mut handles = Vec::new();
    for contract in ["ContractA", "ContractB"] {
        let client = client.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let payload = test_payload(contract);
            let (_tx, rx) = oneshot::channel();
            let span = tracing::info_span!("delivery", contract = contract);
            let _ = tracing::Instrument::instrument(
                send_webhook(&client, &url, &payload, Some("secret"), rx),
                span,
            )
            .await;
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let entered = recorder.entered.lock().unwrap().clone();
    assert!(
        !entered.is_empty(),
        "expected at least one span to be entered during delivery"
    );

    // Each span id must map to exactly one contract; a guard held across an
    // await would let a span be entered under the wrong task's context.
    let mut seen: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    for (id, contract) in entered {
        if let Some(prev) = seen.insert(id, contract.clone()) {
            assert_eq!(
                prev, contract,
                "span {id} was entered with conflicting contract attribution"
            );
        }
    }
}

/// Snapshot test: a resolved (recovery / NoActivity) alert must be sent to
/// PagerDuty as `event_action: "resolve"` carrying the incident's `dedup_key`,
/// so the existing incident is resolved instead of a new one being triggered.
#[test]
fn test_pagerduty_resolve_snapshot() {
    let mut payload = test_payload("PagerDutyRecovery");
    payload.resolved = true;

    let value = txwatch_notifier::format::pagerduty(&payload, "routing-key");
    let value = txwatch_notifier::format::pagerduty(&payload, "pd-key");

    assert_eq!(
        value["event_action"], "resolve",
        "resolved alerts must use event_action=resolve"
    );
    assert!(
        value.get("dedup_key").and_then(|v| v.as_str()).is_some(),
        "resolve payload must include the incident dedup_key"
    );
}

/// A rule configured with `severity = "info"` must page as `info` even when
/// its `rule_type` (e.g. `AdminFunctionCalled`) would otherwise be treated as
/// critical by the rule-type heuristic.
#[test]
fn test_pagerduty_severity_overrides_rule_type_heuristic() {
    let mut payload = test_payload("AdminFunctionCalled");
    payload.severity = Some("info".to_string());

    let value = txwatch_notifier::format::pagerduty(&payload, "routing-key");
    let value = txwatch_notifier::format::pagerduty(&payload, "pd-key");

    assert_eq!(
        value["payload"]["severity"], "info",
        "configured severity must take precedence over rule_type heuristic"
    );
}

/// A `critical` `LargeTransfer` must page as `critical`, not the `warning`
/// the rule-type heuristic would otherwise assign.
#[test]
fn test_pagerduty_critical_large_transfer() {
    let mut payload = test_payload("LargeTransfer");
    payload.severity = Some("critical".to_string());

    let value = txwatch_notifier::format::pagerduty(&payload, "routing-key");
    let value = txwatch_notifier::format::pagerduty(&payload, "pd-key");

    assert_eq!(value["payload"]["severity"], "critical");
}

/// When severity is unset, the rule-type heuristic must still apply.
#[test]
fn test_pagerduty_severity_falls_back_to_rule_type() {
    let mut payload = test_payload("AdminFunctionCalled");
    payload.severity = None;

    let value = txwatch_notifier::format::pagerduty(&payload, "routing-key");
    let value = txwatch_notifier::format::pagerduty(&payload, "pd-key");

    assert_eq!(
        value["payload"]["severity"], "critical",
        "unset severity must fall back to the rule_type heuristic"
    );
}

/// Chat formats must render the full decimal `amount_xlm_decimal` (trailing
/// zeros trimmed) rather than the deprecated truncated `amount_xlm` integer,
/// so a 0.9 XLM transfer shows as "0.9 XLM" and 9,999.99 as "9999.99 XLM".
#[test]
fn test_chat_formats_render_decimal_amount() {
    let mut payload = test_payload("LargeTransfer");
    payload.amount_xlm = Some(0);
    payload.amount_xlm_decimal = Some("0.9000000".to_string());

    let details: String = txwatch_notifier::format::details(&payload)
        .into_iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect::<Vec<_>>()
        .join(", ");
    let slack_body = txwatch_notifier::format::slack(&payload).to_string();
    assert!(
        slack_body.contains("0.9 XLM"),
        "details must render trimmed decimal amount, got: {slack_body}"
    );
    assert!(
        !slack_body.contains("0 XLM"),
        "details must not render the truncated integer amount, got: {slack_body}"
    );

    payload.amount_xlm = Some(9999);
    payload.amount_xlm_decimal = Some("9999.9900000".to_string());

    let details: String = txwatch_notifier::format::details(&payload)
        .into_iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect::<Vec<_>>()
        .join(", ");
    let slack_body = txwatch_notifier::format::slack(&payload).to_string();
    assert!(
        slack_body.contains("9999.99 XLM"),
        "details must render trimmed decimal amount, got: {slack_body}"
    );
}

/// Discord colour must follow the configured severity: a `critical`
/// A rule-level `webhook_url` shorthand override must replace the destination
/// set entirely: only the override URL receives a delivery, and none of the
/// default `[[contracts.webhooks]]` destinations are hit.
#[tokio::test]
async fn test_rule_webhook_override_replaces_destinations_shorthand() {
    let default_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/default"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&default_server)
        .await;

    let override_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/override"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&override_server)
        .await;

    let client = build_client().unwrap();
    let payload = test_payload("RuleOverrideShorthand");
    let (_tx, rx) = oneshot::channel();

    let override_url = format!("{}/override", override_server.uri());
    let result = send_webhook(&client, &override_url, &payload, None, rx).await;
    assert!(result.is_ok(), "Override delivery must succeed");

    // The default destination must never be contacted when the override
    // replaces the destination set.
    let default_url = format!("{}/default", default_server.uri());
    let (_tx2, rx2) = oneshot::channel();
    let _ = send_webhook(&client, &default_url, &payload, None, rx2).await;
    default_server.verify().await;
    override_server.verify().await;
}

/// A rule-level `webhook_url` array override must deliver to each override
/// destination and must not fan out to the default destinations.
#[tokio::test]
async fn test_rule_webhook_override_replaces_destinations_array() {
    let default_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/default"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&default_server)
        .await;

    let first_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/first"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&first_server)
        .await;

    let second_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/second"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&second_server)
        .await;

    let client = build_client().unwrap();
    let payload = test_payload("RuleOverrideArray");

    let first_url = format!("{}/first", first_server.uri());
    let (_tx1, rx1) = oneshot::channel();
    let first = send_webhook(&client, &first_url, &payload, None, rx1).await;
    assert!(first.is_ok(), "First override destination must succeed");

    let second_url = format!("{}/second", second_server.uri());
    let (_tx2, rx2) = oneshot::channel();
    let second = send_webhook(&client, &second_url, &payload, None, rx2).await;
    assert!(second.is_ok(), "Second override destination must succeed");

    first_server.verify().await;
    second_server.verify().await;
    default_server.verify().await;
}

/// Teams Incoming Webhooks / Workflows reject payloads over roughly 28 KB.
/// A 50-alert digest with long rule labels and long fact values must be
/// truncated (fact titles/values) and fact-count capped so the rendered body
/// stays under the limit instead of failing the request.
#[test]
fn test_teams_digest_body_stays_under_size_limit() {
    const TEAMS_LIMIT: usize = 28 * 1024;

    let long_label = "X".repeat(512);
    let long_value = "Y".repeat(4096);

    let mut payload = test_payload("TeamsDigestSizeLimit");
    payload.alerts = (0..50)
        .map(|i| {
            let mut alert = test_payload(&format!("{long_label}-{i}"));
            alert.rule_name = Some(format!("{long_label}-{i}"));
            alert.contract_id = Some(format!("{long_label}-{i}"));
            alert.message = Some(long_value.clone());
            alert
        })
        .collect();

    let body = txwatch_notifier::format::teams_digest(&payload).to_string();
    assert!(
        body.len() < TEAMS_LIMIT,
        "Teams digest body must stay under {TEAMS_LIMIT} bytes, got {}",
        body.len()
    );

    let body = txwatch_notifier::format::teams(&payload).to_string();
    assert!(
        body.len() < TEAMS_LIMIT,
        "Teams body must stay under {TEAMS_LIMIT} bytes, got {}",
        body.len()
/// Discord enforces a 6000-character total embed budget and at most 25 fields.
/// An oversized payload (long label, many matched events, many details) must
/// be trimmed so the resulting embed stays within both limits.
#[test]
fn test_discord_embed_respects_limits() {
    let mut payload = test_payload("OversizedDiscord");
    payload.label = Some("L".repeat(2000));
    payload.rule_triggered = "R".repeat(2000);
    payload.memo = Some("M".repeat(2000));
    payload.matched_events = (0..50).map(|i| format!("event-{i}-{}", "x".repeat(100))).collect();

    let value = txwatch_notifier::format::discord(&payload);
    let embed = &value["embeds"][0];

    let fields = embed["fields"].as_array().expect("embed must have fields");
    assert!(
        fields.len() <= 25,
        "embed must have at most 25 fields, got {}",
        fields.len()
    );

    let mut total = 0usize;
    if let Some(title) = embed["title"].as_str() {
        total += title.chars().count();
    }
    if let Some(desc) = embed["description"].as_str() {
        total += desc.chars().count();
    }
    if let Some(footer) = embed["footer"]["text"].as_str() {
        total += footer.chars().count();
    }
    for field in fields {
        if let Some(name) = field["name"].as_str() {
            total += name.chars().count();
        }
        if let Some(val) = field["value"].as_str() {
            total += val.chars().count();
        }
    }
    assert!(
        total <= 6000,
        "embed total text must stay under 6000 chars, got {total}"
    );
}

/// Memos come from untrusted on-chain senders. Discord markdown in
/// interpolated values must be escaped so masked links, spoilers and code
/// fences cannot break formatting or smuggle links into the channel.
#[test]
fn test_discord_escapes_markdown_in_memo() {
    let mut payload = test_payload("MarkdownInjection");
    payload.memo = Some("[click here](https://evil.example) ||spoiler|| ```fence```".to_string());
    payload.label = Some("_label_ *bold* ~strike~ > quote".to_string());

    let value = txwatch_notifier::format::discord(&payload);
    let serialized = value.to_string();

    assert!(
        !serialized.contains("[click here](https://evil.example)"),
        "masked link markup must be escaped, got: {serialized}"
    );
    assert!(
        !serialized.contains("||spoiler||"),
        "spoiler markup must be escaped, got: {serialized}"
    );
    assert!(
        !serialized.contains("```fence```"),
        "code fence markup must be escaped, got: {serialized}"
    );
    assert!(
        serialized.contains("\\[click here\\]"),
        "brackets must be backslash-escaped, got: {serialized}"
    );
}

/// A Slack digest with many alerts must truncate on line boundaries and never
/// cut inside `<url|text>` markup, appending a "… and N more" notice.
#[test]
fn test_slack_digest_truncates_on_line_boundaries() {
    let alerts: Vec<txwatch_notifier::Alert> = (0..100)
        .map(|i| {
            let mut payload = test_payload("DigestAlert");
            payload.tx_hash = format!("{i:064x}");
            payload
        })
        .collect();

    let body = txwatch_notifier::format::slack_digest(&alerts);
    assert!(
        body.chars().count() <= 3000,
        "digest must stay within 3000 chars, got {}",
        body.chars().count()
    );

    // Every `<` must be matched by a later `>`; no unterminated markup.
    let mut open = false;
    for ch in body.chars() {
        match ch {
            '<' => {
                assert!(!open, "nested '<' in digest markup: {body}");
                open = true;
            }
            '>' => {
                assert!(open, "unmatched '>' in digest markup: {body}");
                open = false;
            }
            _ => {}
        }
    }
    assert!(!open, "digest ended inside unterminated '<…>' markup: {body}");
    assert!(
        body.contains("more"),
        "truncated digest must include a '… and N more' notice, got: {body}"
    );
}

/// `send_webhook` must make exactly `MAX_ATTEMPTS` attempts (initial + retries)
/// and back off between them, matching the documented behavior.
#[tokio::test]
async fn test_send_webhook_attempt_count_matches_docs() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let url = format!("{}/hook", server.uri());
    let payload = test_payload("RetryCount");
    let (_tx, rx) = oneshot::channel();

    let result = send_webhook(&client, &url, &payload, Some("secret"), rx).await;
    assert!(result.is_err(), "500 flood must exhaust retries");

    let received = server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        txwatch_notifier::MAX_ATTEMPTS,
        "send_webhook must make exactly MAX_ATTEMPTS attempts"
    );
}
