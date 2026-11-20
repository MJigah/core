//! End-to-end check of the `metrics` feature: run a mocked poll, then scrape
//! the HTTP endpoint started by `serve_metrics` on port 0.
#![cfg(feature = "metrics")]

mod helpers;

use std::time::Duration;

use tokio::sync::watch;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use txwatch_config::{AlertRule, AppConfig};

#[tokio::test]
async fn mocked_poll_is_reflected_in_metrics_endpoint() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::tx_page(
            "metrics001",
            "700",
            true,
        )))
        .up_to_n_times(1)
        .mount(&horizon)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;
    Mock::given(method("GET"))
        .and(path("/transactions/metrics001/operations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;

    let mut contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::AnyTransaction],
    );
    contract.label = "Metrics Test Contract".into();
    contract.horizon_base_url_override = Some(horizon.uri());
    let cfg = AppConfig {
        poll_interval_seconds: 5,
        contracts: vec![contract],
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
        readiness_policy: Default::default(),
        ..Default::default()
    };

    // The endpoint keeps running for the scrape; only the poller is stopped.
    let (_server_tx, server_rx) = watch::channel(false);
    let addr = txwatch_poller::serve_metrics("127.0.0.1:0".parse().unwrap(), server_rx)
        .await
        .expect("start metrics endpoint");

    // Signal shutdown up front: the poller runs one full cycle, then returns.
    let (poller_tx, poller_rx) = watch::channel(false);
    poller_tx.send(true).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        txwatch_poller::run_with_shutdown(cfg, false, poller_rx),
    )
    .await
    .expect("poll cycle should finish")
    .expect("poller should succeed");

    let body = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .expect("scrape /metrics")
        .text()
        .await
        .unwrap();
    let labels = r#"{contract="Metrics Test Contract",network="testnet"}"#;
    assert!(
        body.contains(&format!("txwatch_transactions_total{labels} 1")),
        "{body}"
    );
    assert!(
        body.contains(&format!("txwatch_alerts_total{labels} 1")),
        "{body}"
    );
    assert!(
        body.contains(&format!("txwatch_consecutive_poll_failures{labels} 0")),
        "{body}"
    );
    assert!(
        body.contains("txwatch_horizon_request_duration_seconds_count"),
        "{body}"
    );
    assert!(
        body.contains("txwatch_horizon_rate_limited_total"),
        "{body}"
    );

    let ready = reqwest::get(format!("http://{addr}/readyz")).await.unwrap();
    assert_eq!(ready.status(), 200);
    let missing = reqwest::get(format!("http://{addr}/nope")).await.unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test]
async fn horizon_rate_limit_is_reflected_in_metrics_endpoint() {
    let horizon = MockServer::start().await;

    // Every Horizon page request is rate limited.
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&horizon)
        .await;

    let mut contract = helpers::contract("http://127.0.0.1:1/hook", vec![AlertRule::AnyTransaction]);
    contract.label = "Rate Limited Contract".into();
    contract.horizon_base_url_override = Some(horizon.uri());
    let cfg = AppConfig {
        poll_interval_seconds: 5,
        contracts: vec![contract],
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
        readiness_policy: Default::default(),
        ..Default::default()
    };

    let (_server_tx, server_rx) = watch::channel(false);
    let addr = txwatch_poller::serve_metrics("127.0.0.1:0".parse().unwrap(), server_rx)
        .await
        .expect("start metrics endpoint");

    let (poller_tx, poller_rx) = watch::channel(false);
    poller_tx.send(true).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        txwatch_poller::run_with_shutdown(cfg, false, poller_rx),
    )
    .await
    .expect("poll cycle should finish")
    .expect("poller should succeed");

    let body = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .expect("scrape /metrics")
        .text()
        .await
        .unwrap();
    let labels = r#"{contract="Rate Limited Contract",network="testnet"}"#;
    assert!(
        body.contains(&format!("txwatch_horizon_rate_limited_total{labels} 1")),
        "{body}"
    );
    // A rate-limited poll must not be reported as a successful poll.
    assert!(
        body.contains(&format!("txwatch_consecutive_poll_failures{labels} 1")),
        "{body}"
    );
}

#[tokio::test]
async fn operations_fetch_failure_is_reflected_in_degraded_metric() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::tx_page(
            "degraded001",
            "701",
            true,
        )))
        .up_to_n_times(1)
        .mount(&horizon)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;
    // Every operations fetch fails: the transaction is evaluated without
    // operation details and must be counted as degraded.
    Mock::given(method("GET"))
        .and(path("/transactions/degraded001/operations"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&horizon)
        .await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;

    let mut contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::AnyTransaction],
    );
    contract.label = "Degraded Test Contract".into();
    contract.horizon_base_url_override = Some(horizon.uri());
    let cfg = AppConfig {
        poll_interval_seconds: 5,
        contracts: vec![contract],
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
        readiness_policy: Default::default(),
        ..Default::default()
    };

    let (_server_tx, server_rx) = watch::channel(false);
    let addr = txwatch_poller::serve_metrics("127.0.0.1:0".parse().unwrap(), server_rx)
        .await
        .expect("start metrics endpoint");

    let (poller_tx, poller_rx) = watch::channel(false);
    poller_tx.send(true).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        txwatch_poller::run_with_shutdown(cfg, false, poller_rx),
    )
    .await
    .expect("poll cycle should finish")
    .expect("poller should succeed");

    let body = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .expect("scrape /metrics")
        .text()
        .await
        .unwrap();
    let labels = r#"{contract="Degraded Test Contract",network="testnet"}"#;
    assert!(
        body.contains(&format!("txwatch_transactions_degraded_total{labels} 1")),
        "{body}"
    );
}

#[tokio::test]
async fn reload_removes_series_of_dropped_contracts() {
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    let config = |label: &str| {
        let mut contract = helpers::contract("http://127.0.0.1:9/hook", vec![]);
        contract.label = label.into();
        contract.horizon_base_url_override = Some(horizon.uri());
        AppConfig {
            poll_interval_seconds: 5,
            contracts: vec![contract],
            cursor_file: None,
            http_pool_max_idle_per_host: 10,
            http_tcp_keepalive_secs: 30,
            http_connection_verbose: None,
            max_contracts: None,
            max_pages_per_cycle: None,
            readiness_policy: Default::default(),
            ..Default::default()
        }
    };

    let (_server_tx, server_rx) = watch::channel(false);
    let addr = txwatch_poller::serve_metrics("127.0.0.1:0".parse().unwrap(), server_rx)
        .await
        .expect("start metrics endpoint");

    let scrape = || async {
        reqwest::get(format!("http://{addr}/metrics"))
            .await
            .expect("scrape /metrics")
            .text()
            .await
            .unwrap()
    };
    let old = r#"txwatch_consecutive_poll_failures{contract="Reload Old",network="testnet"}"#;
    let new = r#"txwatch_consecutive_poll_failures{contract="Reload New",network="testnet"}"#;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(1);
    let poller = tokio::spawn(txwatch_poller::run_with_reload(
        config("Reload Old"),
        false,
        shutdown_rx,
        reload_rx,
    ));

    let wait_for = |want: &'static str, present: bool| async move {
        for _ in 0..100 {
            if scrape().await.contains(want) == present {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "{want} present={present} never observed:\n{}",
            scrape().await
        );
    };
    wait_for(old, true).await;

    reload_tx.send(config("Reload New")).await.unwrap();
    wait_for(new, true).await;
    let body = scrape().await;
    assert!(!body.contains(old), "{body}");
    assert!(
        !body.contains(r#"txwatch_last_successful_poll_timestamp_seconds{contract="Reload Old""#),
        "{body}"
    );

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), poller)
        .await
        .expect("poller should stop")
        .unwrap()
        .expect("poller should succeed");
}

/// Every metric family documented in the metrics module header must be
/// registered and emitted by `prometheus::gather()`.
#[tokio::test]
async fn all_documented_metric_families_are_emitted() {
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    let mut contract = helpers::contract("http://127.0.0.1:9/hook", vec![]);
    contract.label = "Doc Families Contract".into();
    contract.horizon_base_url_override = Some(horizon.uri());
    let cfg = AppConfig {
        poll_interval_seconds: 5,
        contracts: vec![contract],
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
        readiness_policy: Default::default(),
        ..Default::default()
    };

    let (_server_tx, server_rx) = watch::channel(false);
    let addr = txwatch_poller::serve_metrics("127.0.0.1:0".parse().unwrap(), server_rx)
        .await
        .expect("start metrics endpoint");

    let (poller_tx, poller_rx) = watch::channel(false);
    poller_tx.send(true).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        txwatch_poller::run_with_shutdown(cfg, false, poller_rx),
    )
    .await
    .expect("poll cycle should finish")
    .expect("poller should succeed");

    let body = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .expect("scrape /metrics")
        .text()
        .await
        .unwrap();

    // The documented families, matching the module header exactly.
    let documented = [
        "txwatch_transactions_total",
        "txwatch_transactions_degraded_total",
        "txwatch_alerts_total",
        "txwatch_consecutive_poll_failures",
        "txwatch_last_successful_poll_timestamp_seconds",
        "txwatch_poll_duration_seconds",
        "txwatch_horizon_request_duration_seconds",
        "txwatch_horizon_rate_limited_total",
        "txwatch_event_fetch_failures_total",
        "txwatch_webhook_delivery_duration_seconds",
        "txwatch_webhook_deliveries_total",
    ];

    // Compare against the registered families from prometheus::gather().
    let gathered: Vec<String> = prometheus::gather()
        .into_iter()
        .map(|mf| mf.get_name().to_string())
        .collect();

    for family in documented {
        assert!(
            gathered.iter().any(|name| name == family),
            "documented family {family} is not registered; gathered: {gathered:?}"
        );
        assert!(
            body.contains(family),
            "documented family {family} missing from /metrics body:\n{body}"
        );
    }
}

/// `HEAD` requests must be treated like `GET` (without a body) on all
/// endpoints so load balancers and uptime checkers see a healthy pod.
#[tokio::test]
async fn head_requests_are_accepted_on_all_endpoints() {
    let (_server_tx, server_rx) = watch::channel(false);
    let addr = txwatch_poller::serve_metrics("127.0.0.1:0".parse().unwrap(), server_rx)
        .await
        .expect("start metrics endpoint");

    let client = reqwest::Client::new();
    for endpoint in ["/metrics", "/healthz", "/readyz"] {
        let resp = client
            .head(format!("http://{addr}{endpoint}"))
            .send()
            .await
            .expect("send HEAD");
        assert_eq!(resp.status(), 200, "HEAD {endpoint}");
        let body = resp.text().await.unwrap();
        assert!(body.is_empty(), "HEAD {endpoint} must have empty body: {body}");
    }
}

/// Non-GET/HEAD methods must be rejected with 405 and an `Allow` header.
#[tokio::test]
async fn unsupported_methods_get_405_with_allow_header() {
    let (_server_tx, server_rx) = watch::channel(false);
    let addr = txwatch_poller::serve_metrics("127.0.0.1:0".parse().unwrap(), server_rx)
        .await
        .expect("start metrics endpoint");

    let client = reqwest::Client::new();
    for endpoint in ["/metrics", "/healthz", "/readyz"] {
        let resp = client
            .post(format!("http://{addr}{endpoint}"))
            .send()
            .await
            .expect("send POST");
        assert_eq!(resp.status(), 405, "POST {endpoint}");
        let allow = resp
            .headers()
            .get(reqwest::header::ALLOW)
            .expect("Allow header present")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            allow.contains("GET") && allow.contains("HEAD"),
            "Allow header on POST {endpoint}: {allow}"
        );
    }
}

/// Many idle connections must not prevent the server from serving a
/// subsequent request (bounded concurrency + header read timeout).
#[tokio::test]
async fn idle_connections_do_not_starve_server() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    let (_server_tx, server_rx) = watch::channel(false);
    let addr = txwatch_poller::serve_metrics("127.0.0.1:0".parse().unwrap(), server_rx)
        .await
        .expect("start metrics endpoint");

    // Open a batch of connections that never send a request (slowloris).
    let mut idle = Vec::new();
    for _ in 0..64 {
        match TcpStream::connect(addr).await {
            Ok(stream) => idle.push(stream),
            Err(_) => break,
        }
    }
    // Send a partial request header on a few of them to exercise the timeout.
    for stream in idle.iter_mut().take(8) {
        let _ = stream.write_all(b"GET /metrics HTTP/1.1\r\n").await;
    }

    // The server must still answer a normal request promptly.
    let body = tokio::time::timeout(
        Duration::from_secs(5),
        reqwest::get(format!("http://{addr}/metrics")),
    )
    .await
    .expect("server should respond despite idle connections")
    .expect("scrape /metrics")
    .text()
    .await
    .unwrap();
    assert!(body.contains("txwatch_transactions_total"), "{body}");

    drop(idle);
}