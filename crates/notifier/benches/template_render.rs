use criterion::{black_box, criterion_group, criterion_main, Criterion};
use notifier::alert::{AlertPayload, AlertSeverity};
use notifier::template::{render_template, TemplateCache};

fn representative_payload() -> AlertPayload {
    AlertPayload {
        contract_id: "CABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string(),
        event_type: "contract_event".to_string(),
        severity: AlertSeverity::Warning,
        message: "Contract emitted a warning-level event during batch processing".to_string(),
        ledger: 123_456,
        timestamp: 1_700_000_000,
        fields: [
            ("batch_size".to_string(), "128".to_string()),
            ("gas_used".to_string(), "987654".to_string()),
            ("function".to_string(), "transfer".to_string()),
        ]
        .into_iter()
        .collect(),
    }
}

const TEMPLATE_BODY: &str = "\
[{{ severity }}] Contract {{ contract_id }} at ledger {{ ledger }}
Event: {{ event_type }}
Message: {{ message }}
Batch size: {{ fields.batch_size }}
Gas used: {{ fields.gas_used }}
Function: {{ fields.function }}
";

fn bench_render_template(c: &mut Criterion) {
    let payload = representative_payload();
    let mut cache = TemplateCache::new();
    cache
        .compile("bench-destination", TEMPLATE_BODY)
        .expect("template should compile");

    let mut group = c.benchmark_group("template_render");
    group.bench_function("cached_destination_body", |b| {
        b.iter(|| {
            let rendered = render_template(
                black_box(&cache),
                black_box("bench-destination"),
                black_box(&payload),
            )
            .expect("template should render");
            black_box(rendered);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_render_template);
criterion_main!(benches);