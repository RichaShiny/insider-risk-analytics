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

## Hugging Face security data and analyst features

Import bounded samples directly from **WitFoo's original dataset**, rather than an unverified mirror:

```bash
python security_data.py import-hf --config signals --limit 500
python security_data.py import-hf --config incident_signals --limit 500
python security_data.py imports
python security_data.py evaluate
python insiderlens.py report
python security_data.py export --output queue.csv
```

Dataset: https://huggingface.co/datasets/witfoo/precinct6-cybersecurity-100m

Attribution: WitFoo, Inc. (2026), *WitFoo Precinct6 Cybersecurity Dataset (large)*, v2.1.0, Apache-2.0. Data remains in your local database; raw records are not committed to this repository. The project's MIT license does not replace the dataset's Apache-2.0 terms.

The publisher describes sanitized production SOC data. `signals` is an archived 2024 capture, while `incident_signals` contains historical incident leads. These are **real-source historical research records**, not real-time employee monitoring and not a validated insider-threat benchmark. CERT datasets were considered but are synthetic and are not substituted here.

### Import controls and provenance

- Select `--offset` and `--limit` (1 to 10,000) for bounded pagination without downloading the 100M+ corpus.
- Each import stores dataset ID, observed repository revision, config, offset, fetched time, row counts, rejection count, and a SHA-256 digest of downloaded records.
- The viewer API serves current data, not revision-pinned snapshots. Revision checks before and after the download detect changes to the source repository, but cannot guarantee the viewer cache is at that revision. The digest identifies the received payload. Exact snapshot replay would require an archived payload or revision-pinned Parquet download, neither is claimed here.
- Imports reject partial/truncated viewer responses and retry transient network failures. Stable artifact IDs deduplicate repeat imports. A different dataset revision gets a separate source namespace.
- Missing account identifiers fall back to an explicitly typed host or unresolved-event identity. Organization namespaces prevent unrelated accounts from being merged.
- Timestamp preserves the dataset's `timestamp` field, which may be platform ingest time or lead-observation time, not device event time. `timestamp_source` and `event_time` are retained in provenance.
- Labels, suspicion scores, incident statuses, and ATT&CK mappings are never detection inputs. ATT&CK mappings remain research metadata.

### Investigation and review

Find an actor in the report or SQLite event table, then inspect its chronological history:

```bash
python security_data.py timeline 'ORG-0001/account:USER-0001'
# Replace source and event ID below with an actual alert's values:
python security_data.py review SOURCE EVENT_ID needs-investigation 'Checking access context'
python security_data.py review SOURCE EVENT_ID benign 'Approved activity confirmed'
python insiderlens.py report
```

Reviews append to history, so a later disposition does not erase the earlier one. This is a local analyst convenience, not a tamper-proof audit system. CSV exports escape common spreadsheet formula prefixes. The HTML report now includes event mix, sample label composition, entity types, and review history.

### Evaluation limits

`evaluate` reports a confusion matrix, precision, recall, and false-positive rate **against the source's automated labels**, separately for each revision/config. Suspicious or unknown labels are excluded, and undefined metrics are `null`. These are descriptive agreement statistics for the loaded sample. The incident-lead subset is positive-only and cannot estimate a false-positive rate. Contiguous bounded samples are not representative of the full dataset.

No supervised model is trained, so no held-out predictive performance is claimed. The detector remains deliberately simple: raw authentication failure types map to review leads, while per-event volume is 1 because this dataset does not provide compatible transfer volume. The existing volume-spike rule remains useful for authorized JSONL sources with actual volume measurements. Low recall on historical incident labels is expected and should guide future detector work rather than be hidden.
