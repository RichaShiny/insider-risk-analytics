import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import insiderlens as core
import security_data as data


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.db = core.connect(':memory:'); data.setup(self.db)

    def tearDown(self): self.db.close()

    def row(self):
        return dict(artifact_id='a1',org_id='ORG-1',timestamp=1700000000,
                    username='USER-1',message_type='auth_failure',label_binary='malicious')

    def test_labels_do_not_change_detection_input(self):
        row = self.row()
        a,_ = data.convert(row,'signals','rev')
        row.update(label_binary='benign',suspicion_score=1,attack_techniques='["T1000"]')
        b,_ = data.convert(row,'signals','rev')
        self.assertEqual(a,b)

    def test_org_scoped_identity_and_unknowns(self):
        row = self.row()
        first,_ = data.convert(row,'signals','rev')
        row['org_id'] = 'ORG-2'
        second,_ = data.convert(row,'signals','rev')
        self.assertNotEqual(first['actor'],second['actor'])
        row['username'] = ''
        _,meta = data.convert(row,'signals','rev')
        self.assertEqual(meta['actor_type'],'unresolved-event')

    def test_import_idempotency_and_manifest(self):
        responses = [{'sha':'rev'},{'rows':[{'row':self.row(),'truncated_cells':[]}],'partial':False},{'sha':'rev'}]
        for expected in (1,0):
            with patch('security_data.get_json',side_effect=responses):
                result = data.import_hf(self.db,limit=1)
            self.assertEqual(result['inserted'],expected)
        self.assertEqual(self.db.execute('SELECT count(*) FROM imports').fetchone()[0],2)
        self.assertEqual(data.evaluate(self.db)['hf-witfoo:rev:signals']['tp'],1)

    def test_changed_dataset_aborts(self):
        with patch('security_data.get_json',side_effect=[{'sha':'one'},{'rows':[]},{'sha':'two'}]):
            with self.assertRaises(ValueError): data.import_hf(self.db,limit=1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM events').fetchone()[0],0)

    def test_review_keeps_history(self):
        event,_ = data.convert(self.row(),'signals','rev'); core.ingest(self.db,event)
        for verdict in ('needs-investigation','benign'):
            data.review(self.db,event['source'],event['id'],verdict,'test note')
        self.assertEqual(self.db.execute('SELECT count(*) FROM reviews').fetchone()[0],2)
        with self.assertRaises(ValueError): data.review(self.db,'missing','id','benign','')

    def test_export_and_timeline(self):
        event,_ = data.convert(self.row(),'signals','rev'); event['actor']='=formula'
        core.ingest(self.db,event)
        self.assertEqual(len(data.timeline(self.db,'=formula')),1)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'queue.csv'; data.export_queue(self.db,path)
            self.assertIn("'=formula",path.read_text())

    def test_no_positive_labels_has_undefined_recall(self):
        row = self.row(); row['label_binary']='benign'
        event,meta = data.convert(row,'signals','rev'); core.ingest(self.db,event)
        self.db.execute('INSERT INTO provenance VALUES (?,?,?)',(event['source'],event['id'],json.dumps(meta)))
        stats = data.evaluate(self.db)[event['source']]
        self.assertIsNone(stats['recall'])
        self.assertEqual(stats['fp'],1)
