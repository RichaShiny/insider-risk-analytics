"""Streaming, evidence-based activity triage. Python 3.10+, no dependencies."""
import argparse
import hashlib
import html
import json
import os
import sqlite3
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def utc(value):
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timestamp must include timezone')
    return dt.astimezone(timezone.utc)


def connect(path):
    db = sqlite3.connect(path)
    db.executescript('''
    CREATE TABLE IF NOT EXISTS events (
      source TEXT, id TEXT, actor TEXT, timestamp TEXT, kind TEXT,
      resource TEXT, volume REAL, sensitive INTEGER, received_at TEXT,
      PRIMARY KEY(source,id));
    CREATE INDEX IF NOT EXISTS actor_time ON events(source,actor,timestamp);
    CREATE TABLE IF NOT EXISTS alerts (
      source TEXT, event_id TEXT, score INTEGER, reasons TEXT,
      PRIMARY KEY(source,event_id));
    CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
    ''')
    return db


def normalize(raw):
    required = ('id', 'source', 'actor', 'timestamp', 'kind')
    if any(not isinstance(raw.get(k), str) or not raw[k].strip() for k in required):
        raise ValueError('nonempty string fields required: ' + ', '.join(required))
    if raw['source'] == 'github-public':
        raise ValueError('github-public is reserved for the public feed adapter')
    dt = utc(raw['timestamp'])
    volume = float(raw.get('volume', 0))
    import math
    if not math.isfinite(volume) or volume < 0:
        raise ValueError('volume must be finite and nonnegative')
    if type(raw.get('sensitive', False)) is not bool:
        raise ValueError('sensitive must be boolean')
    return dict(raw, timestamp=dt.isoformat(), volume=volume)


def ingest(db, event):
    """Score against strictly earlier history; duplicate events never change state."""
    stamp = utc(event['timestamp']).isoformat()
    source, actor = event['source'], event['actor']
    if db.execute('SELECT 1 FROM events WHERE source=? AND id=?', (source,event['id'])).fetchone():
        return False
    history = db.execute('SELECT volume FROM events WHERE source=? AND actor=? AND kind=? AND timestamp<? ORDER BY timestamp DESC LIMIT 100',
                         (source,actor,event['kind'],stamp)).fetchall()
    reasons = []
    if source != 'github-public':
        if event['kind'] == 'access_denied':
            reasons.append('Access denied event; review authorization context')
        if event['kind'] == 'dlp_alert' and event.get('sensitive', False):
            reasons.append('DLP source marked this event as sensitive')
        if len(history) >= 20:
            values = [r[0] for r in history]
            median = statistics.median(values)
            mad = statistics.median(abs(v-median) for v in values)
            threshold = median + max(6 * 1.4826 * mad, 10, abs(median)*2)
            if event.get('volume',0) > threshold:
                reasons.append(f'Volume {event["volume"]:g} exceeds prior-history threshold {threshold:g} ({len(values)} events, same actor and kind)')
    with db:
        db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',
                   (source,event['id'],actor,stamp,event['kind'],str(event.get('resource','')),
                    event.get('volume',0),int(event.get('sensitive',False)),datetime.now(timezone.utc).isoformat()))
        if reasons:
            db.execute('INSERT INTO alerts VALUES (?,?,?,?)', (source,event['id'],min(100,30*len(reasons)),json.dumps(reasons)))
    return True


def poll_github(db):
    headers = {'Accept':'application/vnd.github+json','User-Agent':'InsiderLens-portfolio'}
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    row = db.execute("SELECT value FROM state WHERE key='etag'").fetchone()
    if row:
        headers['If-None-Match'] = row[0]
    try:
        response = urlopen(Request('https://api.github.com/events?per_page=100',headers=headers),timeout=30)
    except HTTPError as exc:
        if exc.code == 304:
            return 0, 60
        raise
    with response:
        records = json.load(response)
        interval = max(60,int(response.headers.get('X-Poll-Interval','60')))
        etag = response.headers.get('ETag')
    # Oldest first so the ingestion history is chronological within this batch.
    count = 0
    for raw in sorted(records,key=lambda r:r['created_at']):
        event = {'id':raw['id'],'source':'github-public',
                 'actor':hashlib.sha256(str(raw['actor']['id']).encode()).hexdigest()[:16],
                 'timestamp':raw['created_at'],'kind':raw['type'],
                 'resource':raw['repo']['name'],'volume':0,'sensitive':False}
        count += ingest(db,event)
    with db:
        if etag:
            db.execute('INSERT OR REPLACE INTO state VALUES (?,?)',('etag',etag))
        db.execute('INSERT OR REPLACE INTO state VALUES (?,?)',('last_poll',datetime.now(timezone.utc).isoformat()))
    return count, interval


def report(db, path):
    rows = db.execute('SELECT e.source,e.actor,e.timestamp,e.kind,a.score,a.reasons FROM alerts a JOIN events e ON e.source=a.source AND e.id=a.event_id ORDER BY e.timestamp DESC LIMIT 200').fetchall()
    summary = db.execute('SELECT source,count(*),max(timestamp),max(received_at) FROM events GROUP BY source').fetchall()
    def table(items):
        return ''.join('<tr>'+''.join('<td>'+html.escape(str(v))+'</td>' for v in row)+'</tr>' for row in items)
    document = '''<!doctype html><html lang="en"><meta charset="utf-8"><title>InsiderLens</title>
    <style>body{font:16px system-ui;background:#101827;color:#e6edf7;max-width:1200px;margin:40px auto;padding:20px}td,th{padding:12px;text-align:left;border-bottom:1px solid #36445e}table{width:100%;border-collapse:collapse}p{line-height:1.6}h1{color:#62dbbd}</style>
    <h1>InsiderLens · Activity triage</h1><p>Public GitHub activity is a delayed, incomplete ingestion demo. It is never scored as insider risk. Alerts from supplied organizational telemetry are review leads, not findings of misconduct. Scores are rule priorities, not probabilities.</p>
    <h2>Source freshness</h2><table><tr><th>Source</th><th>Events</th><th>Newest event (UTC)</th><th>Latest receipt (UTC)</th></tr>'''+table(summary)+'''</table>
    <h2>Investigation queue</h2><table><tr><th>Source</th><th>Actor</th><th>Event time</th><th>Kind</th><th>Priority</th><th>Evidence</th></tr>'''+table(rows)+'''</table><p>No alerts may mean insufficient history or no triggering events. It does not establish safety.</p></html>'''
    Path(path).write_text(document,encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db',default='activity.db')
    sub = parser.add_subparsers(dest='command',required=True)
    poll = sub.add_parser('poll',help='Poll live public activity, once by default')
    poll.add_argument('--watch',action='store_true')
    load = sub.add_parser('ingest',help='Read authorized telemetry JSONL, or - for stdin')
    load.add_argument('file')
    view = sub.add_parser('report')
    view.add_argument('--output',default='report.html')
    args = parser.parse_args()
    db = connect(args.db)
    try:
        if args.command == 'poll':
            while True:
                count,interval = poll_github(db)
                print(json.dumps({'inserted':count,'next_poll_seconds':interval}),flush=True)
                if not args.watch:
                    break
                time.sleep(interval)
        elif args.command == 'ingest':
            stream = sys.stdin if args.file == '-' else open(args.file,encoding='utf-8')
            inserted = rejected = 0
            try:
                for number,line in enumerate(stream,1):
                    if not line.strip():
                        continue
                    try:
                        inserted += ingest(db,normalize(json.loads(line)))
                    except (ValueError,TypeError,KeyError) as exc:
                        rejected += 1
                        print(f'Line {number} rejected: {exc}',file=sys.stderr)
            finally:
                if stream is not sys.stdin:
                    stream.close()
            print(json.dumps({'inserted':inserted,'rejected':rejected}))
            if rejected:
                return 1
        else:
            report(db,args.output)
    finally:
        db.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
