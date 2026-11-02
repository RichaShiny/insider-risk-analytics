"""Hugging Face imports, provenance and analyst workflows. Standard library only."""
import argparse
import csv
import hashlib
import json
import math
import time
from datetime import datetime, timezone
from urllib.parse import urlencode
from urllib.request import urlopen
from urllib.error import HTTPError, URLError
import insiderlens as core
DATASET = 'witfoo/precinct6-cybersecurity-100m'


def setup(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS provenance(source TEXT,event_id TEXT,metadata TEXT,PRIMARY KEY(source,event_id));
    CREATE TABLE IF NOT EXISTS imports(run_id INTEGER PRIMARY KEY,manifest TEXT);
    CREATE TABLE IF NOT EXISTS reviews(review_id INTEGER PRIMARY KEY,source TEXT,event_id TEXT,disposition TEXT,note TEXT,reviewed_at TEXT);
    ''')


def get_json(url):
    for attempt in range(3):
        try:
            with urlopen(url,timeout=40) as response:
                return json.load(response)
        except (HTTPError,URLError) as exc:
            if isinstance(exc,HTTPError) and exc.code not in (429,500,502,503,504):
                raise
            if attempt == 2:
                raise
            time.sleep(2**attempt)


def convert(row,config,revision):
    if not isinstance(row,dict) or not row.get('artifact_id') or not row.get('org_id'):
        raise ValueError('artifact_id and org_id required')
    stamp = row.get('timestamp')
    if not isinstance(stamp,(int,float)) or not math.isfinite(stamp):
        raise ValueError('finite timestamp required')
    actor_type = 'account' if row.get('username') else 'host' if row.get('src_host') else 'unresolved-event'
    identity = row.get('username') or row.get('src_host') or row['artifact_id']
    kind = row.get('message_type') or 'unknown'
    if kind.lower() in ('auth_failure','logon_failure','4625'):
        kind = 'access_denied'
    event = dict(id=str(row['artifact_id']),source=f'hf-witfoo:{revision}:{config}',
        actor=row['org_id']+'/'+actor_type+':'+str(identity),
        timestamp=datetime.fromtimestamp(stamp,timezone.utc).isoformat(),kind=kind,
        resource=str(row.get('dst_host') or row.get('src_host') or ''),volume=1,sensitive=False)
    # Labels and incident-derived scores never enter the detector.
    keys = ('label_binary','label_confidence','disposition_category','origin','timestamp_source','event_time','attack_techniques','product_name','org_id')
    metadata = {k:row.get(k) for k in keys}
    metadata.update(dataset=DATASET,revision=revision,config=config,actor_type=actor_type)
    return event,metadata


def import_hf(db,config='signals',limit=1000,offset=0):
    if config not in ('signals','incident_signals') or not 1 <= limit <= 10000 or offset < 0:
        raise ValueError('limit must be 1..10000, offset >= 0, config signals or incident_signals')
    revision = get_json('https://huggingface.co/api/datasets/'+DATASET)['sha']
    records = []
    for start in range(offset,offset+limit,100):
        length = min(100,offset+limit-start)
        url = 'https://datasets-server.huggingface.co/rows?'+urlencode(dict(dataset=DATASET,config=config,split='train',offset=start,length=length))
        page = get_json(url)
        if page.get('partial') or any(r.get('truncated_cells') for r in page['rows']):
            raise ValueError('partial/truncated dataset response')
        records.extend(r['row'] for r in page['rows'])
        if len(page['rows']) < length:
            break
    if get_json('https://huggingface.co/api/datasets/'+DATASET)['sha'] != revision:
        raise ValueError('Dataset changed during fetch; retry')
    normalized = []
    rejected = 0
    for row in records:
        try:
            normalized.append(convert(row,config,revision))
        except (ValueError,TypeError,OverflowError):
            rejected += 1
    inserted = 0
    for event,meta in sorted(normalized,key=lambda pair:pair[0]['timestamp']):
        inserted += core.ingest(db,event)
        with db:
            db.execute('INSERT OR IGNORE INTO provenance VALUES (?,?,?)',(event['source'],event['id'],json.dumps(meta)))
    manifest = dict(dataset=DATASET,config=config,revision_observed=revision,offset=offset,requested=limit,
        downloaded=len(records),inserted=inserted,rejected=rejected,
        payload_sha256=hashlib.sha256(json.dumps(records,sort_keys=True).encode()).hexdigest(),
        fetched_at=datetime.now(timezone.utc).isoformat())
    with db:
        db.execute('INSERT INTO imports VALUES (NULL,?)',(json.dumps(manifest),))
    return manifest


def evaluate(db):
    groups = {}
    for source,event_id,metadata in db.execute('SELECT * FROM provenance'):
        meta = json.loads(metadata)
        stats = groups.setdefault(source,dict(tp=0,fp=0,tn=0,fn=0,excluded=0))
        label = meta.get('label_binary')
        if label not in ('malicious','benign'):
            stats['excluded'] += 1
            continue
        predicted = bool(db.execute('SELECT 1 FROM alerts WHERE source=? AND event_id=?',(source,event_id)).fetchone())
        key = ('tp' if predicted else 'fn') if label == 'malicious' else ('fp' if predicted else 'tn')
        stats[key] += 1
    for stats in groups.values():
        tp,fp,tn,fn = (stats[k] for k in ('tp','fp','tn','fn'))
        stats.update(precision=tp/(tp+fp) if tp+fp else None,recall=tp/(tp+fn) if tp+fn else None,
            false_positive_rate=fp/(fp+tn) if fp+tn else None,
            warning='Agreement with automated labels on bounded nonrandom samples, not independent ground truth or population performance.')
    return groups


def review(db,source,event_id,disposition,note):
    if disposition not in ('needs-investigation','benign','confirmed-incident'):
        raise ValueError('invalid disposition')
    if not db.execute('SELECT 1 FROM alerts WHERE source=? AND event_id=?',(source,event_id)).fetchone():
        raise ValueError('alert not found')
    with db:
        db.execute('INSERT INTO reviews VALUES (NULL,?,?,?,?,?)',(source,event_id,disposition,note,datetime.now(timezone.utc).isoformat()))


def timeline(db,actor):
    return db.execute('SELECT source,id,timestamp,kind,resource FROM events WHERE actor=? ORDER BY timestamp LIMIT 200',(actor,)).fetchall()


def export_queue(db,path):
    with open(path,'w',newline='',encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(['source','event_id','actor','timestamp','kind','priority','reasons'])
        for row in db.execute('SELECT e.source,e.id,e.actor,e.timestamp,e.kind,a.score,a.reasons FROM alerts a JOIN events e ON e.source=a.source AND e.id=a.event_id ORDER BY a.score DESC,e.timestamp DESC'):
            writer.writerow(["'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r')) else v for v in row])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db',default='activity.db')
    sub = p.add_subparsers(dest='command',required=True)
    hf = sub.add_parser('import-hf')
    hf.add_argument('--config',choices=['signals','incident_signals'],default='signals')
    hf.add_argument('--limit',type=int,default=1000)
    hf.add_argument('--offset',type=int,default=0)
    sub.add_parser('evaluate')
    sub.add_parser('imports')
    t = sub.add_parser('timeline'); t.add_argument('actor')
    r = sub.add_parser('review')
    for field in ('source','event_id','disposition','note'):
        r.add_argument(field)
    e = sub.add_parser('export'); e.add_argument('--output',default='queue.csv')
    args = p.parse_args()
    db = core.connect(args.db); setup(db)
    try:
        if args.command == 'import-hf': result = import_hf(db,args.config,args.limit,args.offset)
        elif args.command == 'evaluate': result = evaluate(db)
        elif args.command == 'timeline': result = timeline(db,args.actor)
        elif args.command == 'review':
            review(db,args.source,args.event_id,args.disposition,args.note); result = {'saved':True}
        elif args.command == 'export':
            export_queue(db,args.output); result = {'output':args.output}
        else: result = [json.loads(r[0]) for r in db.execute('SELECT manifest FROM imports ORDER BY run_id DESC')]
        print(json.dumps(result,indent=2))
    finally: db.close()


if __name__ == '__main__': main()
