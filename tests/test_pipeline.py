import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
import insiderlens as app


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.db = app.connect(':memory:')

    def tearDown(self):
        self.db.close()

    def event(self, number=1, **overrides):
        return dict(id=str(number),source='authorized-test',actor='user-1',
                    timestamp=f'2026-01-01T00:{number:02d}:00Z',kind='download',
                    volume=10,sensitive=False,**overrides)

    def test_duplicate_is_idempotent(self):
        self.assertTrue(app.ingest(self.db,self.event()))
        self.assertFalse(app.ingest(self.db,self.event()))
        self.assertEqual(self.db.execute('SELECT count(*) FROM events').fetchone()[0],1)

    def test_baseline_spike_and_evidence(self):
        for n in range(1,21):
            app.ingest(self.db,self.event(n))
        event = self.event(21)
        event['volume'] = 1000
        app.ingest(self.db,event)
        row = self.db.execute('SELECT reasons FROM alerts').fetchone()
        self.assertIn('prior-history threshold',row[0])

    def test_future_history_does_not_leak(self):
        for n in range(2,23):
            app.ingest(self.db,self.event(n))
        event = self.event(1)
        event['volume'] = 1000
        app.ingest(self.db,event)
        self.assertEqual(self.db.execute('SELECT count(*) FROM alerts').fetchone()[0],0)

    def test_public_activity_never_scored(self):
        event = self.event()
        event.update(source='github-public',kind='access_denied',sensitive=True)
        app.ingest(self.db,event)
        self.assertEqual(self.db.execute('SELECT count(*) FROM alerts').fetchone()[0],0)

    def test_invalid_input(self):
        for update in ({'volume':float('nan')},{'timestamp':'2026-01-01'},{'sensitive':'false'},{'source':'github-public'}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                app.normalize(dict(self.event(),**update))

    def test_report_escapes_content(self):
        event = self.event()
        event.update(actor='<script>alert(1)</script>',kind='access_denied')
        app.ingest(self.db,event)
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'report.html'
            app.report(self.db,target)
            self.assertNotIn('<script>',target.read_text())
            self.assertIn('&lt;script&gt;',target.read_text())

    def test_not_modified(self):
        with patch('insiderlens.urlopen',side_effect=HTTPError('url',304,'Not Modified',{},None)):
            self.assertEqual(app.poll_github(self.db),(0,60))


if __name__ == '__main__':
    unittest.main()
