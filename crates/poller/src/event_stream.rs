//! Real-time Soroban contract event streaming via JSON-RPC `getEvents`.
//! Replaces legacy REST polling with direct contract topic and event parsing.
//!
//! Supports two delivery modes per contract:
//! - [`StreamMode::Poll`] (default): interval polling via RPC `getEvents`.
//! - [`StreamMode::Stream`]: Horizon Server-Sent Events (`Accept: text/event-stream`)
//!   that resume from the last seen paging token on reconnect and fall back to
//!   polling after repeated disconnects.

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Delivery mode for a contract's event feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StreamMode {
    /// Interval polling via RPC `getEvents` (preserves existing behavior).
    #[default]
    Poll,
    /// Horizon Server-Sent Events on collection endpoints.
    Stream,
}

/// Number of consecutive stream disconnects before falling back to polling.
pub const MAX_STREAM_DISCONNECTS: u32 = 3;

/// Client name sent to Horizon/RPC operators for identification and fair rate limiting.
const CLIENT_NAME: &str = "txwatch";
/// Client version sent to Horizon/RPC operators for identification.
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// JSON-RPC 2.0 Request envelope.
#[derive(Debug, Serialize)]
struct JsonRpcRequest<T> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: T,
}

/// Parameters for Soroban RPC `getEvents`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetEventsParams {
    pub start_ledger: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<EventFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<PaginationParams>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EventFilter {
    #[serde(rename = "type")]
    pub event_type: String,
    pub contract_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub topics: Vec<Vec<String>>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PaginationParams {
    pub limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// JSON-RPC 2.0 Response envelope.
#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetEventsResult {
    pub events: Vec<SorobanEvent>,
    pub latest_ledger: u64,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// A parsed Soroban contract event emitted on-chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SorobanEvent {
    pub id: String,
    pub contract_id: String,
    pub ledger: u64,
    pub ledger_closed_at: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub topic: Vec<String>,
    pub value: serde_json::Value,
    pub in_successful_contract_call: bool,
}

/// A single Server-Sent Event frame parsed from a Horizon stream.
#[derive(Debug, Clone, PartialEq)]
pub struct SseEvent {
    /// SSE `event:` field (e.g. `"message"` or `"hello"`).
    pub event: String,
    /// SSE `id:` field, used as the paging token for resumption.
    pub id: Option<String>,
    /// SSE `data:` field payload.
    pub data: String,
}

/// Parses a raw SSE frame (fields separated by newlines) into an [`SseEvent`].
///
/// Returns `None` for comment-only or empty frames, which Horizon uses as
/// keep-alives and should be ignored by the consumer.
pub fn parse_sse_frame(frame: &str) -> Option<SseEvent> {
    let mut event = String::from("message");
    let mut id = None;
    let mut data_lines: Vec<&str> = Vec::new();

    for line in frame.lines() {
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match field {
            "event" => event = value.to_string(),
            "id" => id = Some(value.to_string()),
            "data" => data_lines.push(value),
            _ => {}
        }
    }

    if data_lines.is_empty() {
        return None;
    }

    Some(SseEvent {
        event,
        id,
        data: data_lines.join("\n"),
    })
}

/// Real-time Soroban contract event streaming engine.
///
/// Supports multiple Horizon/RPC endpoints per network or contract. On a
/// connection error or 5xx response, the streamer falls back to the next
/// configured endpoint for that poll cycle.
pub struct SorobanEventStreamer {
    rpc_urls: Vec<String>,
    active_url: usize,
    contract_ids: Vec<String>,
    last_cursor: Option<String>,
    current_ledger: u64,
    client: Client,
    mode: StreamMode,
    consecutive_disconnects: u32,
}

impl SorobanEventStreamer {
    /// Creates a streamer from a single endpoint (backwards compatible).
    pub fn new(rpc_url: impl Into<String>, contract_ids: Vec<String>, start_ledger: u64) -> Self {
        Self::with_urls(vec![rpc_url.into()], contract_ids, start_ledger)
    }

    /// Creates a streamer from a list of endpoints with failover support.
    ///
    /// The first URL is used until it fails; subsequent polls then start from
    /// the endpoint that last succeeded.
    pub fn with_urls(rpc_urls: Vec<String>, contract_ids: Vec<String>, start_ledger: u64) -> Self {
        Self {
            rpc_urls,
            active_url: 0,
            contract_ids,
            last_cursor: None,
            current_ledger: start_ledger,
            client: build_client(),
            mode: StreamMode::default(),
            consecutive_disconnects: 0,
        }
    }

    /// Sets the delivery mode for this contract's feed.
    pub fn with_mode(mut self, mode: StreamMode) -> Self {
        self.mode = mode;
        self
    }

    /// Returns the currently active delivery mode, accounting for fallback.
    pub fn mode(&self) -> StreamMode {
        self.mode
    }

    /// The last paging token seen, used to resume a stream on reconnect.
    pub fn last_cursor(&self) -> Option<&str> {
        self.last_cursor.as_deref()
    }

    /// Fetches the next batch of real-time Soroban events via RPC `getEvents`.
    ///
    /// Tries each configured endpoint in order, starting from the last known
    /// healthy one, and falls back to the next URL on connection errors or 5xx
    /// responses. The endpoint that served the poll is logged at debug level.
    pub async fn fetch_events(&mut self) -> Result<Vec<SorobanEvent>> {
        if self.rpc_urls.is_empty() {
            return Err(anyhow!("no Horizon/RPC endpoints configured"));
        }

        let filter = EventFilter {
            event_type: "contract".into(),
            contract_ids: self.contract_ids.clone(),
            topics: vec![],
        };

        let params = GetEventsParams {
            start_ledger: self.current_ledger,
            filters: vec![filter],
            pagination: Some(PaginationParams {
                limit: 100,
                cursor: self.last_cursor.clone(),
            }),
        };

        let request_body = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "getEvents",
            params,
        };

        let mut last_error: Option<anyhow::Error> = None;
        let url_count = self.rpc_urls.len();

        for offset in 0..url_count {
            let idx = (self.active_url + offset) % url_count;
            let url = self.rpc_urls[idx].clone();

            match self.try_fetch(&url, &request_body).await {
                Ok(result) => {
                    if idx != self.active_url {
                        info!(endpoint = %url, "failing over to Horizon/RPC endpoint");
                    }
                    self.active_url = idx;

                    if let Some(c) = result.cursor {
                        self.last_cursor = Some(c);
                    }
                    self.current_ledger = result.latest_ledger;

                    debug!(
                        endpoint = %url,
                        events_count = result.events.len(),
                        latest_ledger = result.latest_ledger,
                        "streamed real-time soroban events"
                    );

                    return Ok(result.events);
                }
                Err(err) => {
                    debug!(endpoint = %url, error = %err, "Horizon/RPC endpoint failed, trying next");
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("all Horizon/RPC endpoints failed")))
    }

    /// Attempts a single `getEvents` request against one endpoint.
    async fn try_fetch(
        &self,
        url: &str,
        request_body: &JsonRpcRequest<GetEventsParams>,
    ) -> Result<GetEventsResult> {
        let response = self
            .client
            .post(url)
            .json(request_body)
            .send()
            .await
            .with_context(|| format!("failed to send getEvents RPC request to {url}"))?;

        let status = response.status();
        if status.is_server_error() {
            return Err(anyhow!("Horizon/RPC endpoint {url} returned {status}"));
        }

        let rpc_res: JsonRpcResponse<GetEventsResult> = response
            .json()
            .await
            .with_context(|| format!("failed to parse getEvents RPC response from {url}"))?;

        if let Some(err) = rpc_res.error {
            return Err(anyhow!("RPC getEvents error {}: {}", err.code, err.message));
        }

        rpc_res
            .result
            .ok_or_else(|| anyhow!("missing result in getEvents RPC response"))
    }

    /// Opens a Horizon SSE stream for the configured contracts.
    ///
    /// Resumes from the last seen paging token via the `cursor` query parameter
    /// so no events are missed across reconnects. On repeated disconnects the
    /// streamer falls back to interval polling to keep alerts flowing.
    pub async fn stream_events(&mut self) -> Result<Vec<SorobanEvent>> {
        if self.mode == StreamMode::Poll {
            return self.fetch_events().await;
        }

        match self.open_sse_stream().await {
            Ok(events) => {
                self.consecutive_disconnects = 0;
                Ok(events)
            }
            Err(err) => {
                self.consecutive_disconnects += 1;
                warn!(
                    error = %err,
                    disconnects = self.consecutive_disconnects,
                    "horizon SSE stream disconnected"
                );
                if self.consecutive_disconnects >= MAX_STREAM_DISCONNECTS {
                    warn!(
                        threshold = MAX_STREAM_DISCONNECTS,
                        "falling back to interval polling after repeated stream disconnects"
                    );
                    self.mode = StreamMode::Poll;
                }
                self.fetch_events().await
            }
        }
    }

    /// Performs a single SSE connection attempt against the Horizon endpoint.
    async fn open_sse_stream(&mut self) -> Result<Vec<SorobanEvent>> {
        let mut url = format!(
            "{}/events",
            self.rpc_urls[self.active_url].trim_end_matches('/')
        );
        if let Some(cursor) = &self.last_cursor {
            url = format!("{}?cursor={}", url, cursor);
        }

        let response = self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send()
            .await
            .context("failed to open horizon SSE stream")?;

        if !response.status().is_success() {
            return Err(anyhow!("horizon SSE stream returned {}", response.status()));
        }

        let body = response
            .text()
            .await
            .context("failed to read horizon SSE stream")?;

        let mut events = Vec::new();
        for frame in body.split("\n\n") {
            let Some(sse) = parse_sse_frame(frame) else {
                continue;
            };
            if let Some(id) = sse.id {
                self.last_cursor = Some(id);
            }
            if sse.event == "hello" {
                continue;
            }
            match serde_json::from_str::<SorobanEvent>(&sse.data) {
                Ok(event) => events.push(event),
                Err(err) => debug!(error = %err, "skipping unparsable SSE event payload"),
            }
        }

        info!(events_count = events.len(), "received horizon SSE events");
        Ok(events)
    }

    pub fn current_ledger(&self) -> u64 {
        self.current_ledger
    }
}

/// Builds a reqwest client that identifies txwatch to Horizon/RPC operators.
fn build_client() -> Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_str(&format!("{}/{}", CLIENT_NAME, CLIENT_VERSION))
            .expect("valid user-agent header"),
    );
    headers.insert(
        "X-Client-Name",
        reqwest::header::HeaderValue::from_static(CLIENT_NAME),
    );
    headers.insert(
        "X-Client-Version",
        reqwest::header::HeaderValue::from_static(CLIENT_VERSION),
    );

    Client::builder()
        .default_headers(headers)
        .build()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_event_filter_serialization() {
        let filter = EventFilter {
            event_type: "contract".into(),
            contract_ids: vec!["CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()],
            topics: vec![vec!["transfer".into()]],
        };
        let json = serde_json::to_string(&filter).unwrap();
        assert!(json.contains("contractIds"));
        assert!(json.contains("type"));
        assert!(json.contains("topics"));
    }

    #[tokio::test]
    async fn test_horizon_requests_send_identifying_headers() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header(
                "User-Agent",
                format!("{}/{}", CLIENT_NAME, CLIENT_VERSION).as_str(),
            ))
            .and(header("X-Client-Name", CLIENT_NAME))
            .and(header("X-Client-Version", CLIENT_VERSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "events": [],
                    "latestLedger": 42
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut streamer = SorobanEventStreamer::new(server.uri(), vec![], 1);
        let events = streamer.fetch_events().await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_failover_to_healthy_endpoint_on_5xx() {
        let failing = MockServer::start().await;
        let healthy = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&failing)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "events": [],
                    "latestLedger": 99
                }
            })))
            .expect(1)
            .mount(&healthy)
            .await;

        let mut streamer =
            SorobanEventStreamer::with_urls(vec![failing.uri(), healthy.uri()], vec![], 1);

        let events = streamer.fetch_events().await.unwrap();
        assert!(events.is_empty());
        assert_eq!(streamer.current_ledger(), 99);
    }

    #[tokio::test]
    async fn test_failover_on_connection_error() {
        let healthy = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "events": [],
                    "latestLedger": 7
                }
            })))
            .expect(1)
            .mount(&healthy)
            .await;

        // Unreachable endpoint (no server listening) followed by a healthy one.
        let mut streamer = SorobanEventStreamer::with_urls(
            vec!["http://127.0.0.1:1".into(), healthy.uri()],
            vec![],
            1,
        );

        let events = streamer.fetch_events().await.unwrap();
        assert!(events.is_empty());
        assert_eq!(streamer.current_ledger(), 7);
    }
    #[test]
    fn test_stream_mode_defaults_to_poll() {
        assert_eq!(StreamMode::default(), StreamMode::Poll);
        let streamer = SorobanEventStreamer::new("http://localhost", vec![], 1);
        assert_eq!(streamer.mode(), StreamMode::Poll);
    }

    #[test]
    fn test_parse_sse_frame_extracts_id_and_data() {
        let frame = "event: message\nid: 0000000120\ndata: {\"id\":\"1\"}";
        let parsed = parse_sse_frame(frame).expect("frame should parse");
        assert_eq!(parsed.event, "message");
        assert_eq!(parsed.id.as_deref(), Some("0000000120"));
        assert_eq!(parsed.data, "{\"id\":\"1\"}");
    }

    #[test]
    fn test_parse_sse_frame_ignores_keepalive_comments() {
        assert!(parse_sse_frame(": keep-alive").is_none());
        assert!(parse_sse_frame("").is_none());
    }

    #[test]
    fn test_parse_sse_frame_joins_multiline_data() {
        let frame = "data: line1\ndata: line2";
        let parsed = parse_sse_frame(frame).unwrap();
        assert_eq!(parsed.data, "line1\nline2");
    }
}
