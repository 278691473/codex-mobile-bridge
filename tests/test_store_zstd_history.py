import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import zstandard

from bridge.features.sessions.store import SessionStore, StoreUnavailable


ROOT = Path(__file__).resolve().parents[1]


class StoreZstdHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.tmp')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        for name in ('sessions', 'archived_sessions'):
            (self.home / name).mkdir()
        self.database = self.home / 'state_5.sqlite'
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('CREATE TABLE threads (id TEXT PRIMARY KEY, title TEXT, cwd TEXT, '
                       'updated_at INT, archived INT, originator TEXT, source TEXT, '
                       'thread_source TEXT, rollout_path TEXT)')
        self.store = SessionStore(self.home)
        self.records = [{'type': 'session_meta', 'payload': {'id': 'fixture'}}]
        for index in range(6):
            self.records.extend([
                {'type': 'event_msg', 'payload': {'type': 'task_started', 'turn_id': str(index)}},
                {'type': 'turn_context', 'payload': {'model': 'desktop-model', 'effort': 'high'}},
                {'type': 'response_item', 'payload': {'type': 'message', 'role': 'user',
                 'content': [{'type': 'input_text', 'text': '问题🙂' + str(index)}]}},
                {'type': 'response_item', 'payload': {'type': 'message', 'role': 'assistant',
                 'content': [{'type': 'output_text', 'text': '答🙂' * 12000 + str(index)}]}},
                {'type': 'event_msg', 'payload': {'type': 'task_complete'}},
            ])
        self.raw = ('\n'.join(json.dumps(r, ensure_ascii=False) for r in self.records) + '\n').encode()
        self.plain = self.home / 'sessions' / 'rollout-fixture.jsonl'
        self.compressed = self.plain.with_suffix('.jsonl.zst')

    def register(self, path, *, originator='Codex Desktop', source='vscode', thread_source=None):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('INSERT OR REPLACE INTO threads VALUES (?,?,?,?,?,?,?,?,?)',
                       ('fixture', 'Fixture', '/fixture', 1,
                        int(path.parent.name == 'archived_sessions'), originator, source,
                        thread_source, str(path)))

    def compress(self, raw=None):
        return zstandard.ZstdCompressor(write_content_size=False, write_checksum=True).compress(
            self.raw if raw is None else raw)

    def test_direct_compressed_path_matches_plain_and_complete_turn_pagination(self):
        self.plain.write_bytes(self.raw)
        self.register(self.plain)
        expected = {limit: self.store.history('fixture', limit) for limit in (None, 1, 2, 6, 20)}
        self.compressed.write_bytes(self.compress())
        self.plain.unlink()
        self.register(self.compressed)
        for limit, view in expected.items():
            with self.subTest(limit=limit):
                self.assertEqual(self.store.history('fixture', limit), view)

    def test_missing_plain_uses_only_same_named_compressed_sibling(self):
        self.compressed.write_bytes(self.compress())
        self.register(self.plain)
        view = self.store.history('fixture', 2)
        self.assertEqual([t['turnId'] for t in view['turns']], ['4', '5'])
        self.assertFalse(view['turnsPagination']['hasLoadedOldest'])
        self.assertFalse(self.plain.exists())

    def test_existing_plain_is_preferred_and_needs_no_decoder(self):
        self.plain.write_bytes(self.raw)
        self.compressed.write_bytes(b'corrupt stale copy')
        self.register(self.plain)
        with patch.dict(sys.modules, {'zstandard': None}):
            self.assertEqual(len(self.store.history('fixture')['turns']), 6)

    def test_archived_compressed_history_uses_same_fallback(self):
        path = self.home / 'archived_sessions' / 'rollout-fixture.jsonl'
        path.with_suffix('.jsonl.zst').write_bytes(self.compress())
        self.register(path)
        self.assertEqual(len(self.store.list(archived=True)), 1)
        self.assertEqual(len(self.store.history('fixture')['turns']), 6)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows extended path contract')
    def test_windows_extended_path_keeps_exact_fork_basename(self):
        fork = self.home / 'sessions' / 'rollout-fixture_fork.jsonl'
        fork.with_suffix('.jsonl.zst').write_bytes(self.compress())
        self.register(Path('\\\\?\\' + str(fork)))
        self.assertEqual(len(self.store.history('fixture')['turns']), 6)

    def test_standard_compressed_history_precedes_db_fork_with_same_session_id(self):
        fork = self.home / 'sessions' / 'rollout-fixture_fork.jsonl'
        fork_raw = ('\n'.join(json.dumps(r, ensure_ascii=False) for r in self.records[:6]) + '\n').encode()
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                self.compressed.unlink(missing_ok=True)
                db_path = fork.with_suffix('.jsonl.zst') if compressed else fork
                db_path.write_bytes(self.compress(fork_raw) if compressed else fork_raw)
                self.register(db_path)
                self.assertEqual(len(self.store.history('fixture')['turns']), 1)
                self.compressed.write_bytes(self.compress())
                self.assertEqual(len(self.store.history('fixture')['turns']), 6)

    def test_standard_plain_precedes_compressed_and_db_fork_without_decoder(self):
        self.plain.write_bytes(self.raw)
        self.compressed.write_bytes(b'not selected')
        fork = self.home / 'sessions' / 'rollout-fixture_fork.jsonl.zst'
        fork.write_bytes(b'not selected either')
        self.register(fork)
        with patch.dict(sys.modules, {'zstandard': None}):
            self.assertEqual(len(self.store.history('fixture')['turns']), 6)

    def test_multiple_standard_plain_files_reject_even_with_explicit_db_path(self):
        self.plain.write_bytes(self.raw)
        other = self.home / 'archived_sessions' / 'another-fixture.jsonl'
        other.write_bytes(self.raw)
        self.register(self.plain)
        with self.assertRaisesRegex(StoreUnavailable, '多个'):
            self.store.history('fixture')

    def test_multiple_standard_compressed_files_reject(self):
        self.compressed.write_bytes(self.compress())
        self.register(self.compressed)
        self.assertEqual(len(self.store.history('fixture')['turns']), 6)
        other = self.home / 'archived_sessions' / 'another-fixture.jsonl.zst'
        other.write_bytes(self.compress())
        with self.assertRaisesRegex(StoreUnavailable, '多个'):
            self.store.history('fixture')

    def test_db_fallback_requires_matching_session_metadata(self):
        fork = self.home / 'sessions' / 'rollout-fixture_fork.jsonl'
        self.register(fork)
        headers = [
            {'type': 'session_meta', 'payload': {'id': 'another-thread'}},
            {'type': 'session_meta', 'payload': None},
            {'type': 'response_item', 'payload': {'id': 'fixture'}},
            [],
        ]
        for header in headers:
            with self.subTest(header=header):
                raw = json.dumps(header).encode() + b'\n' + self.raw
                fork.with_suffix('.jsonl.zst').write_bytes(self.compress(raw))
                with self.assertRaisesRegex(StoreUnavailable, '归属'):
                    self.store.history('fixture')
        fork.with_suffix('.jsonl.zst').write_bytes(self.compress(self.raw))
        self.assertEqual(len(self.store.history('fixture')['turns']), 6)

    def test_malformed_db_fallback_does_not_scan_other_fork_files(self):
        fork = self.home / 'sessions' / 'rollout-fixture_fork.jsonl'
        fork.write_bytes(b'not json\n')
        other = self.home / 'sessions' / 'rollout-fixture_other.jsonl.zst'
        other.write_bytes(self.compress())
        self.register(fork)
        with self.assertRaisesRegex(StoreUnavailable, '归属'):
            self.store.history('fixture')

    def test_concatenated_unknown_size_frames_can_split_utf8_and_json_lines(self):
        cut = self.raw.index('问题'.encode()) + 1
        self.compressed.write_bytes(self.compress(self.raw[:cut]) + self.compress(self.raw[cut:]))
        self.register(self.compressed)
        view = self.store.history('fixture')
        self.assertEqual(len(view['turns']), 6)
        self.assertEqual(view['turns'][0]['items'][0]['content'][0]['text'], '问题🙂0')

    def test_bad_truncated_empty_and_trailing_compressed_data_fail_closed(self):
        encoded = self.compress()
        damaged = bytearray(encoded)
        damaged[-1] ^= 1
        for data in (b'', b'not zstd', encoded[:-1], encoded[:12], bytes(damaged), encoded + b'garbage'):
            with self.subTest(length=len(data)):
                self.compressed.write_bytes(data)
                self.register(self.compressed)
                self.store.history_cache.clear()
                with self.assertRaises(StoreUnavailable):
                    self.store.history('fixture')

    def test_valid_empty_frame_has_complete_empty_history(self):
        self.compressed.write_bytes(self.compress(b''))
        self.register(self.compressed)
        view = self.store.history('fixture')
        self.assertEqual(view['turns'], [])
        self.assertTrue(view['turnsPagination']['hasLoadedOldest'])

    def test_missing_decoder_reports_recoverable_error(self):
        self.compressed.write_bytes(self.compress())
        self.register(self.compressed)
        with patch.dict(sys.modules, {'zstandard': None}):
            with self.assertRaisesRegex(StoreUnavailable, 'zstandard'):
                self.store.history('fixture')

    def test_missing_both_files_still_reports_missing_history(self):
        self.register(self.plain)
        with self.assertRaises(FileNotFoundError):
            self.store.history('fixture')

    def test_reads_do_not_rewrite_or_materialize_source_history(self):
        self.compressed.write_bytes(self.compress())
        self.register(self.plain)
        before = hashlib.sha256(self.compressed.read_bytes()).digest()
        names = sorted(str(p.relative_to(self.home)) for p in self.home.rglob('*'))
        self.store.history('fixture', 2)
        self.store.history('fixture')
        self.assertEqual(hashlib.sha256(self.compressed.read_bytes()).digest(), before)
        self.assertEqual(sorted(str(p.relative_to(self.home)) for p in self.home.rglob('*')), names)

    def test_compressed_cache_is_isolated_and_invalidates_after_replacement(self):
        self.compressed.write_bytes(self.compress())
        self.register(self.plain)
        first = self.store.history('fixture', 2)
        first['turns'].clear()
        with patch.object(self.store, '_recent_lines', side_effect=AssertionError('cache miss')):
            self.assertEqual(len(self.store.history('fixture', 2)['turns']), 2)
        previous = self.compressed.stat()
        self.compressed.write_bytes(self.compress(self.raw.replace(b'desktop-model', b'changed-model')))
        os.utime(self.compressed, ns=(previous.st_atime_ns, previous.st_mtime_ns + 1_000_000))
        changed = self.store.history('fixture', 2)
        self.assertEqual(changed['turns'][0]['params']['model'], 'changed-model')

    def test_compressed_path_outside_allowed_roots_is_rejected_before_read(self):
        outside = self.home / 'outside.jsonl.zst'
        outside.write_bytes(self.compress())
        self.register(outside)
        with patch.object(self.store, '_recent_lines') as reader:
            with self.assertRaisesRegex(ValueError, '路径'):
                self.store.history('fixture')
            reader.assert_not_called()

    def test_compressed_sibling_resolved_outside_roots_is_rejected(self):
        outside = self.home / 'outside.jsonl.zst'
        outside.write_bytes(self.compress())
        self.compressed.write_bytes(self.compress())
        self.register(self.plain)
        resolve = Path.resolve

        def redirected(path, *args, **kwargs):
            return outside if path == self.compressed else resolve(path, *args, **kwargs)

        with patch.object(Path, 'resolve', redirected), patch.object(self.store, '_recent_lines') as reader:
            with self.assertRaisesRegex(ValueError, '路径'):
                self.store.history('fixture')
            reader.assert_not_called()

    def test_originator_and_subagent_boundaries_are_preserved(self):
        self.compressed.write_bytes(self.compress())
        cases = [
            {'originator': 'codex_cli'},
            {'thread_source': 'subagent'},
            {'source': '{"subagent":{"thread_spawn":{}}}'},
        ]
        for meta in cases:
            with self.subTest(meta=meta):
                self.register(self.plain, **meta)
                self.assertEqual(self.store.list(), [])
                with patch.object(self.store, '_recent_lines') as reader:
                    with self.assertRaises(KeyError):
                        self.store.history('fixture')
                    reader.assert_not_called()
        self.register(self.plain, originator=None)
        self.assertEqual(len(self.store.history('fixture')['turns']), 6)


if __name__ == '__main__':
    unittest.main()
