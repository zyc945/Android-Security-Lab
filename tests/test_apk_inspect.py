"""Offline ZIP fixtures only: no adb, devices, extraction, or input writes."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest import mock
import zipfile


HELPER = Path(__file__).resolve().parents[1] / 'skills/android-security-lab/scripts/apk_inspect.py'
sys.path.insert(0, str(HELPER.parent))
spec = importlib.util.spec_from_file_location('apk_inspect', HELPER)
apk_inspect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apk_inspect)


class ApkInspectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def apk(self, name='base.apk', entries=None):
        path = self.root / name
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(path, 'w') as archive:
                for entry, value in (entries if entries is not None else [('AndroidManifest.xml', b'fixture')]):
                    archive.writestr(entry, value)
        return path

    def run_helper(self, *paths, cwd=None):
        result = subprocess.run([sys.executable, str(HELPER), *map(str, paths)],
                                cwd=cwd, capture_output=True, text=True, timeout=10,
                                env=dict(os.environ, ADB_BIN='/does/not/exist'))
        report = json.loads(result.stdout)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertEqual(report['operation'], 'apk-inspect')
        self.assertLessEqual(report['started_at'], report['finished_at'])
        self.assertNotIn('adb', report['tools'])
        return result.returncode, report

    def run_main(self, *paths):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = apk_inspect.main(list(map(str, paths)))
        return code, json.loads(out.getvalue())

    def test_wrapper_offline_without_adb_or_device_selection(self):
        path = self.apk(entries=[('lib/arm64-v8a/libflutter.so', b'fixture')])
        before = path.read_bytes()
        wrapper = HELPER.parents[3] / 'bin/android-lab'
        result = subprocess.run([str(wrapper), 'apk-inspect', str(path)], capture_output=True,
                                text=True, timeout=10,
                                env=dict(os.environ, ADB_BIN='/missing/adb',
                                         ANDROID_SERIAL='not-connected', PYTHON=sys.executable))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['artifacts'][0]['framework_candidates'][0]['framework'], 'flutter')
        self.assertEqual(path.read_bytes(), before)

    def manifest(self, artifacts, coverage='complete'):
        path = self.root / 'manifest.json'
        path.write_text(json.dumps({'coverage': coverage, 'artifacts': artifacts}))
        return path

    def artifact(self, apk, **extra):
        return {'relative_path': apk.name, 'size_bytes': apk.stat().st_size,
                'sha256': hashlib.sha256(apk.read_bytes()).hexdigest(), **extra}

    def test_markers_abis_hash_and_scope_without_reading_contents(self):
        apk = self.apk(entries=[('lib/arm64-v8a/libflutter.so', b'flutter'),
                                ('lib/arm64-v8a/libapp.so', b'app'),
                                ('lib/x86/libOther.so', b'other'),
                                ('assets/index.android.bundle', b'react native')])
        original = apk.read_bytes()
        with mock.patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('no member reads')):
            code, report = self.run_main(apk)
        self.assertEqual(code, 0)
        item = report['artifacts'][0]
        self.assertEqual(item['sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(item['size_bytes'], len(original))
        self.assertEqual(item['abis'], ['arm64-v8a', 'x86'])
        self.assertEqual(item['native_library_count'], 3)
        frameworks = {entry['framework']: entry['basis'] for entry in item['framework_candidates']}
        self.assertEqual(set(frameworks), {'flutter', 'react_native'})
        self.assertEqual(frameworks['react_native'], [{'apk_path': str(apk), 'zip_entry': 'assets/index.android.bundle'}])
        self.assertEqual(len(frameworks['flutter']), 2)
        self.assertEqual(report['input_scope'], 'provided_inputs')
        self.assertIsNone(report['source_coverage'])
        self.assertIn('no installed package completeness', report['limitations'][0])
        self.assertIn('do not prove', report['limitations'][2])
        self.assertEqual(apk.read_bytes(), original)

    def test_invalid_and_empty_zip_negative(self):
        invalid = self.root / 'invalid.apk'
        invalid.write_bytes(b'not zip')
        empty = self.apk('empty.apk', [])
        code, report = self.run_helper(invalid, empty)
        self.assertEqual(code, 2)
        self.assertEqual(report['artifacts'], [])
        self.assertEqual(len(report['failures']), 2)
        self.assertEqual(report['inventory_coverage'], 'none')

    def test_complete_and_partial_manifest_without_globbing_or_writes(self):
        apk = self.apk()
        unlisted = self.apk('unlisted.apk', [('lib/x86/libflutter.so', b'ignored')])
        for coverage, expected_code in [('complete', 0), ('partial', 1), ('none', 1)]:
            manifest = self.manifest([self.artifact(apk)], coverage)
            before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (apk, unlisted, manifest)}
            code, report = self.run_helper(self.root)
            self.assertEqual(code, expected_code)
            self.assertEqual(report['source_coverage'], coverage)
            self.assertEqual(report['inventory_coverage'], 'complete')
            self.assertEqual(report['input_scope'], 'manifest_listed_artifacts')
            self.assertEqual(len(report['artifacts']), 1)
            self.assertEqual(report['artifacts'][0]['framework_candidates'], [])
            self.assertEqual({p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before}, before)

    def test_missing_or_malformed_artifacts_keep_other_success(self):
        apk = self.apk()
        self.manifest([self.artifact(apk), {'relative_path': 'missing.apk'}, None,
                       {'relative_path': apk.name, 'size_bytes': True},
                       {'relative_path': apk.name, 'sha256': 123}])
        code, report = self.run_helper(self.root)
        self.assertEqual(code, 1)
        self.assertEqual(len(report['artifacts']), 1)
        self.assertEqual(len(report['failures']), 4)
        self.assertEqual(report['inventory_coverage'], 'partial')
        self.assertEqual(report['source_coverage'], 'complete')

    def test_legacy_local_path_absolute_and_cwd_relative(self):
        apk = self.apk()
        for path, cwd in [(str(apk), '/'), (apk.name, self.root)]:
            self.manifest([{'local_path': path}])
            code, report = self.run_helper(self.root, cwd=cwd)
            self.assertEqual(code, 0)
            self.assertEqual(report['artifacts'][0]['path'], str(apk))
        # A basename is not silently resolved against the manifest directory.
        self.manifest([{'local_path': apk.name}])
        code, report = self.run_helper(self.root, cwd='/')
        self.assertEqual(code, 2)
        self.assertEqual(report['artifacts'], [])

    def test_relative_field_takes_precedence_without_fallback(self):
        apk = self.apk()
        self.manifest([{'relative_path': 'missing.apk', 'local_path': str(apk)}])
        code, report = self.run_helper(self.root)
        self.assertEqual(code, 2)
        self.assertEqual(report['artifacts'], [])

    def test_symlink_outside_and_traversal_are_rejected(self):
        apk = self.apk()
        link = self.root / 'link.apk'
        link.symlink_to(apk)
        directory_link = self.root / 'linked-directory'
        directory_link.symlink_to(self.root, target_is_directory=True)
        outside = self.root.parent / 'outside.apk'
        for artifact in [{'relative_path': link.name}, {'local_path': str(outside)},
                         {'relative_path': '../outside.apk'}, {'relative_path': str(apk)}]:
            self.manifest([artifact])
            code, report = self.run_helper(self.root)
            self.assertEqual(code, 2)
            self.assertFalse(report['artifacts'])
        self.assertEqual(self.run_helper(link)[0], 2)
        self.manifest([self.artifact(apk)])
        self.assertEqual(self.run_helper(directory_link)[0], 0)
        self.manifest([{'relative_path': 'base.apk'}])
        (self.root / 'manifest.json').unlink()
        (self.root / 'manifest.json').symlink_to(apk)
        self.assertEqual(self.run_helper(self.root)[0], 2)

    def test_duplicate_path_and_file_identity(self):
        apk = self.apk()
        alias = self.root / 'alias.apk'
        os.link(apk, alias)
        for paths in [(apk, apk), (apk, alias)]:
            code, report = self.run_helper(*paths)
            self.assertEqual(code, 1)
            self.assertEqual(len(report['artifacts']), 1)
            self.assertEqual(report['failures'][0]['code'], 'duplicate_artifact')
        self.manifest([{'relative_path': apk.name}, {'relative_path': apk.name}])
        self.assertEqual(self.run_helper(self.root)[0], 1)

    def test_manifest_digest_and_size_mismatch(self):
        apk = self.apk()
        for extra in [{'sha256': '0' * 64}, {'size_bytes': apk.stat().st_size + 1}]:
            self.manifest([self.artifact(apk, **extra)])
            code, report = self.run_helper(self.root)
            self.assertEqual(code, 2)
            self.assertEqual(report['failures'][0]['code'], 'manifest_mismatch')
            self.assertFalse(report['artifacts'])

    def test_metadata_budget_rejected_before_zipfile(self):
        apk = self.apk()
        original = apk.read_bytes()
        eocd = original.rfind(b'PK\x05\x06')
        changed = bytearray(original)
        struct.pack_into('<I', changed, eocd + 12, apk_inspect.MAX_METADATA_BYTES + 1)
        apk.write_bytes(changed)
        with mock.patch.object(zipfile, 'ZipFile', side_effect=AssertionError('budget must precede ZipFile')):
            code, report = self.run_main(apk)
        self.assertEqual(code, 2)
        self.assertIn('metadata exceeds budget', report['failures'][0]['error'])
        apk.write_bytes(original)
        with mock.patch.object(apk_inspect, 'MAX_ENTRIES', 0), mock.patch.object(zipfile, 'ZipFile', side_effect=AssertionError):
            self.assertEqual(self.run_main(apk)[0], 2)
        with mock.patch.object(apk_inspect, 'MAX_FILE_BYTES', len(original) - 1), mock.patch.object(zipfile, 'ZipFile', side_effect=AssertionError):
            self.assertEqual(self.run_main(apk)[0], 2)

    def test_zip64_multidisk_bad_layout_and_count_rejected(self):
        apk = self.apk()
        original = apk.read_bytes()
        eocd = original.rfind(b'PK\x05\x06')
        for offset, format_, value in [(4, '<H', 1), (8, '<H', 65535), (16, '<I', 0xffffffff),
                                       (16, '<I', 1), (8, '<H', 2)]:
            changed = bytearray(original)
            struct.pack_into(format_, changed, eocd + offset, value)
            apk.write_bytes(changed)
            self.assertEqual(self.run_helper(apk)[0], 2)

    def test_invalid_paths_duplicates_and_nonregular_entries(self):
        for index, name in enumerate(['../lib/x86/libapp.so', 'lib/../libapp.so',
                                      'lib/x86/libapp\x00.so', 'lib/x86/libapp\n.so',
                                      '/lib/x86/libapp.so', 'lib\\x86\\libapp.so',
                                      'C:/lib/x86/libapp.so', 'lib/x86/libapp\x85.so', 'folder//', 'x' * 1025]):
            apk = self.apk(str(index) + '.apk', [(name.replace('\x00', 'X'), b'fixture')])
            if '\x00' in name:
                apk.write_bytes(apk.read_bytes().replace(b'libappX.so', b'libapp\x00.so'))
            code, report = self.run_helper(apk)
            self.assertEqual(code, 2, name)
            self.assertFalse(report['artifacts'])
        for name in ['lib/x86/libapp.so', 'assets/index.android.bundle']:
            apk = self.apk(entries=[(name, b'first'), (name, b'second')])
            self.assertEqual(self.run_helper(apk)[0], 2)
        info = zipfile.ZipInfo('lib/x86/libapp.so')
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        apk = self.apk(entries=[(info, b'symlink target')])
        self.assertEqual(self.run_helper(apk)[0], 2)

    def test_library_truncation_and_abi_budget(self):
        apk = self.apk(entries=[('lib/x86/lib{}.so'.format(index), b'lib') for index in range(3)])
        with mock.patch.object(apk_inspect, 'MAX_LIBRARIES', 2):
            code, report = self.run_main(apk)
        self.assertEqual(code, 1)
        item = report['artifacts'][0]
        self.assertEqual(len(item['native_libraries']), 2)
        self.assertEqual(item['native_library_count'], 3)
        self.assertTrue(item['libraries_truncated'])
        apk = self.apk(entries=[('lib/x86/liba.so', b'a'), ('lib/arm64-v8a/libb.so', b'b')])
        with mock.patch.object(apk_inspect, 'MAX_ABIS', 1):
            self.assertEqual(self.run_main(apk)[0], 2)

    def test_artifact_change_after_metadata_snapshot(self):
        apk = self.apk()
        original = apk_inspect.zip_budget
        def mutate(stream, size):
            value = original(stream, size)
            apk.write_bytes(apk.read_bytes() + b'changed')
            return value
        with mock.patch.object(apk_inspect, 'zip_budget', side_effect=mutate):
            code, report = self.run_main(apk)
        self.assertEqual(code, 2)
        self.assertEqual(report['failures'][0]['code'], 'artifact_changed')
        self.assertFalse(report['artifacts'])

    def test_setup_limits_invalid_manifest_and_empty_selection(self):
        self.assertEqual(self.run_helper()[0], 2)
        self.assertEqual(self.run_helper(*(['missing.apk'] * 33))[0], 2)
        for manifest in [{'coverage': 'unknown', 'artifacts': []}, {'coverage': 'complete', 'artifacts': {}},
                         {'coverage': 'complete', 'artifacts': [None] * 33}, {'coverage': 'complete', 'artifacts': []}]:
            (self.root / 'manifest.json').write_text(json.dumps(manifest))
            self.assertEqual(self.run_helper(self.root)[0], 2)
        (self.root / 'manifest.json').write_bytes(b'x' * (apk_inspect.MAX_METADATA_BYTES + 1))
        with mock.patch.object(apk_inspect.json, 'loads', side_effect=AssertionError('budget before JSON parsing')):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(apk_inspect.main([str(self.root)]), 2)

    def test_parent_alias_allowed_but_manifest_internal_alias_rejected(self):
        apk = self.apk()
        alias = self.root / 'parent-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.run_helper(alias / apk.name)[0], 0)
        self.manifest([{'relative_path': 'parent-alias/' + apk.name}])
        self.assertEqual(self.run_helper(self.root)[0], 2)
        self.manifest([{'local_path': str(alias / apk.name)}])
        self.assertEqual(self.run_helper(self.root)[0], 2)

    def test_file_replacement_is_changed_even_when_bytes_match(self):
        apk = self.apk()
        original = apk_inspect.zip_budget
        def replace(stream, size):
            metadata = original(stream, size)
            replacement = self.root / 'replacement.apk'
            replacement.write_bytes(apk.read_bytes())
            replacement.replace(apk)
            return metadata
        with mock.patch.object(apk_inspect, 'zip_budget', side_effect=replace):
            code, report = self.run_main(apk)
        self.assertEqual(code, 2)
        self.assertEqual(report['failures'][0]['code'], 'artifact_changed')

    def test_deeply_nested_manifest_produces_json_failure(self):
        (self.root / 'manifest.json').write_text('[' * 2000 + '0' + ']' * 2000)
        self.assertEqual(self.run_helper(self.root)[0], 2)

    def test_diagnostics_bounded(self):
        apk = self.apk()
        with mock.patch.object(apk_inspect, 'inspect', return_value=(None, ('zip_metadata', 'invalid_artifact', ValueError('x' * 5000)))):
            code, report = self.run_main(apk)
        self.assertEqual(code, 2)
        error = report['failures'][0]
        self.assertEqual(len(error['error']), 2048)
        self.assertTrue(error['error_truncated'])


if __name__ == '__main__':
    unittest.main()
