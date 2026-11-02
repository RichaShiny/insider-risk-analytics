# InsiderLens | Insider Risk Analytics

An executable activity ingestion and explainable triage project. Uses real, live-fetched public GitHub activity to demonstrate ingestion and accepts authorized organizational events through streaming JSONL for insider-risk rules and behavioral baselines. No synthetic records are silently substituted for live data.

## Run

Python 3.10 or later. No third-party dependencies or paid services required.

```bash
python insiderlens.py poll
python insiderlens.py report --output report.html
# Open report.html in your browser
python insiderlens.py poll --watch
```

Optionally set `GITHUB_TOKEN` in your environment for authenticated API limits. Never put credentials in code. The poller honors ETags and the server poll interval, uses timeouts, and preserves SQLite state between runs. Failures are surfaced rather than replaced with demo records. Restart after an API failure or rate-limit reset.

## What “live” means here

The public GitHub Events API is a real source, but is **not a real-time feed**. GitHub documents latency of 30 seconds to 6 hours and a limited timeline. This implementation requests the newest 100 events per poll, so events can be missed on a busy global feed. It is a sampling demo, not a complete audit trail. The report exposes event and receipt times.

Public GitHub activity is **never scored as insider risk**. It lacks employment context, access entitlements, private file activity, DLP telemetry, and incident labels. Actor IDs are pseudonymized, not anonymized. Public activity does not establish malicious intent.

Source: https://docs.github.com/en/rest/activity/events

## Stream authorized telemetry

Normalize your own approved source into this schema. The example below is a schema illustration, not a real incident:

```json
{"id":"unique-event-id","source":"corporate-dlp","actor":"pseudonymous-id","timestamp":"2026-01-01T12:00:00Z","kind":"dlp_alert","resource":"classified-document","volume":1,"sensitive":true}
```

```bash
python insiderlens.py ingest /path/to/authorized-events.jsonl
# Continuously ingest a producer's flushed JSONL output:
your-authorized-event-producer | python insiderlens.py ingest -
python insiderlens.py report
```

Fields: `id`, `source`, `actor`, timezone-aware `timestamp`, and `kind` are required strings. `volume` is a nonnegative finite number in consistent units per source and event kind. `sensitive` is boolean. Use a stable actor ID across an approved source. `github-public` is reserved. Malformed rows are rejected with line numbers and cause a nonzero exit status while valid rows remain committed.

## Detection and interpretation

- Explicit `access_denied` events and sensitive `dlp_alert` events create review leads.
- Volume spikes compare with up to 100 strictly earlier events for the same source, actor, and kind, after a 20-event warmup.
- Threshold = median + max(6 × 1.4826 × MAD, 10, 2 × abs(median)). This is an illustrative robust baseline, not a calibrated production detector.
- Alerts include observed values and thresholds. Priority is a rule count, not a probability of wrongdoing.
- Late-arriving events are scored against available earlier history. Existing alerts are not retrospectively recomputed. Feed chronologically for reproducible backfills.
- No incident ground truth is supplied. Precision, recall, and business impact are not claimed. An absence of alerts is not evidence of safety.

The SQLite primary key `(source, id)` makes ingestion idempotent. A source must provide stable unique IDs. Actor baselines are source-specific, so identity resolution across systems must happen upstream. No cross-source employee profiling is inferred.

## Architecture

```text
Public GitHub API ── live adapter ──┐
                                  ├── SQLite events ── HTML freshness report
Authorized JSONL ── validation ────┘       │
                                  prior-history rules
                                          │
                                  evidence-based queue
```

## Verification

```bash
python -m unittest discover -s tests -v
```

Tests cover duplicate handling, behavioral spikes, temporal leakage, public-source separation, malformed input, HTML escaping, and conditional polling. Network smoke testing is separate from deterministic tests.

## Operational boundaries

This local portfolio tool has no authentication, encryption layer, RBAC, retention scheduler, or analyst disposition store. Keep organizational data in an approved environment, restrict filesystem access, and apply organizational retention and access policies before supplying sensitive data. Generated databases and reports are ignored by Git. Do not publish employee telemetry or reports to this public repository. Alerts require human review with business context.

Next steps: authorized SIEM connectors, retention and deletion controls, replay evaluation on labeled data, peer baselines, audit logs, and analyst feedback. This version intentionally uses inspectable rules rather than presenting an unvalidated ML model as a security control.
