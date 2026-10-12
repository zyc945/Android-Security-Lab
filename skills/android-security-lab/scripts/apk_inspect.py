#!/usr/bin/env python3
"""Read bounded APK ZIP metadata and hashes; no device or extraction is needed."""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import unicodedata
import zipfile

from lab_common import error_code, report_metadata, utc_now


MAX_APKS = 32
MAX_FILE_BYTES = 2 * 1024 ** 3
MAX_METADATA_BYTES = 8 * 1024 ** 2
MAX_ENTRIES = 100000
MAX_PATH = 1024
MAX_ABIS = 32
MAX_LIBRARIES = 500
ERROR_LIMIT = 2048
LIMITATIONS = [
    "Only supplied APKs or manifest-listed artifacts are inspected; no installed package completeness is proven.",
    "ABI directories and framework markers are packaging clues, not runtime or ELF validation.",
    "Absent markers mean only not found in inspected APKs; they do not prove an application does not use a framework.",
    "Only ZIP metadata is read: no extraction, native code, ELF or Dart snapshot parsing; ZIP64 and multi-volume ZIPs are unsupported.",
    "ZIP structure inventory does not validate APK installability; native paths are conventional lib/<ABI>/<name>.so members.",
    "Rejected artifacts have unknown inventory; capped library lists are explicitly partial. Null source coverage means no pull manifest was supplied.",
]


def failure(report, path, stage, code, error):
    message = str(error)
    report['failures'].append({'path': path, 'stage': stage, 'code': code,
                               'error': message[:ERROR_LIMIT],
                               'error_truncated': len(message) > ERROR_LIMIT})


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def check_path(path, root=None):
    for component in (path, *path.parents):
        if component.is_symlink() and (root is None or component == path or component.parent.resolve().is_relative_to(root)):
            raise ValueError('symlink paths are not accepted')


def open_regular(path):
    check_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('input must be a regular file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(fd, 'rb')
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or identity(before) != identity(os.fstat(fd)):
            raise ValueError('artifact changed while opening')
    except BaseException:
        stream.close()
        raise
    return stream, before


def unchanged(stream, path, before):
    check_path(path)
    if (identity(before) != identity(os.fstat(stream.fileno())) or
            identity(before) != identity(path.lstat())):
        raise ValueError('artifact changed during inspection')


def zip_budget(stream, size):
    if size > MAX_FILE_BYTES:
        raise ValueError('APK exceeds file size budget')
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    # A terminal EOCD with exact comment length avoids guessing about ZIP layout.
    offset = tail.rfind(b'PK\x05\x06')
    if offset < 0 or len(tail) - offset < 22:
        raise ValueError('ZIP end record not found')
    _, disk, cd_disk, disk_count, count, cd_size, cd_start, comment = struct.unpack_from('<4s4H2IH', tail, offset)
    eocd_start = size - len(tail) + offset
    if offset + 22 + comment != len(tail):
        raise ValueError('cannot confirm terminal ZIP end record')
    if (disk or cd_disk or disk_count != count or count == 65535 or
            cd_size == 0xffffffff or cd_start == 0xffffffff or
            tail[max(0, offset - 20):offset].startswith(b'PK\x06\x07')):
        raise ValueError('ZIP64 or multi-volume ZIP is unsupported')
    if not count:
        raise ValueError('empty ZIP has no APK inventory')
    if count > MAX_ENTRIES or cd_size > MAX_METADATA_BYTES:
        raise ValueError('ZIP metadata exceeds budget')
    if cd_start + cd_size != eocd_start or cd_size < count * 46:
        raise ValueError('cannot confirm bounded central directory')
    stream.seek(cd_start)
    central = stream.read(cd_size)
    if len(central) != cd_size:
        raise ValueError('central directory is incomplete')
    # ZipFile sees only this bounded metadata snapshot, even if the APK changes.
    metadata = central + tail[offset:]
    stream.seek(0)
    return count, metadata


def valid_entry(name):
    parts = (name[:-1] if name.endswith('/') else name).split('/')
    return (bool(name) and len(name) <= MAX_PATH and not name.startswith('/') and
            '\\' not in name and all(part and part not in ('.', '..') for part in parts) and
            not re.match(r'^[A-Za-z]:', name) and
            not any(unicodedata.category(char) in ('Cc', 'Cs') for char in name))


def inspect(path, expected):
    stage = 'open'
    stream = None
    before = None
    try:
        stream, before = open_regular(path)
        stage = 'zip_metadata'
        count, metadata = zip_budget(stream, before.st_size)
        stage = 'digest'
        digest = hashlib.sha256()
        read_bytes = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            read_bytes += len(chunk)
            if read_bytes > before.st_size:
                raise ValueError('artifact changed during hashing')
            digest.update(chunk)
        sha = digest.hexdigest()
        if ((expected.get('size_bytes') is not None and expected['size_bytes'] != before.st_size) or
                (expected.get('sha256') is not None and expected['sha256'].lower() != sha)):
            raise ValueError('manifest size or SHA-256 does not match artifact')
        stage = 'zip_metadata'
        abis, libraries, candidates, related = set(), [], {}, set()
        library_count = 0
        with zipfile.ZipFile(io.BytesIO(metadata)) as archive:
            entries = archive.infolist()
            if len(entries) != count or len(entries) > MAX_ENTRIES:
                raise ValueError('central directory entry count is inconsistent')
            for entry in entries:
                if entry.extract_version >= 45:
                    raise ValueError('ZIP64 or extended ZIP formats are unsupported')
                name = entry.orig_filename
                if not valid_entry(name) or name != entry.filename:
                    raise ValueError('invalid ZIP entry path: ' + repr(name))
                parts = name.split('/')
                native = len(parts) == 3 and parts[0] == 'lib' and parts[2].endswith('.so')
                rn = name == 'assets/index.android.bundle'
                if not native and not rn:
                    continue
                if name in related:
                    raise ValueError('duplicate relevant ZIP entry: ' + name)
                related.add(name)
                if entry.is_dir() or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG):
                    raise ValueError('framework/library entry is not a regular ZIP member: ' + name)
                if native:
                    abis.add(parts[1])
                    if len(abis) > MAX_ABIS:
                        raise ValueError('ABI count exceeds budget')
                    library_count += 1
                    if len(libraries) < MAX_LIBRARIES:
                        libraries.append({'path': name, 'abi': parts[1], 'size_bytes': entry.file_size})
                framework = 'flutter' if native and parts[2] in ('libapp.so', 'libflutter.so') else 'react_native' if rn else None
                if framework:
                    candidates.setdefault(framework, []).append({'apk_path': str(path), 'zip_entry': name})
        stage = 'verify_unchanged'
        unchanged(stream, path, before)
        return {'path': str(path), 'size_bytes': before.st_size, 'sha256': sha,
                'abis': sorted(abis), 'native_libraries': libraries,
                'native_library_count': library_count, 'libraries_truncated': library_count > MAX_LIBRARIES,
                'framework_candidates': [{'framework': framework, 'basis': basis}
                                         for framework, basis in sorted(candidates.items())]}, None
    except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError) as exc:
        code = 'manifest_mismatch' if stage == 'digest' and isinstance(exc, ValueError) else 'invalid_artifact'
        if isinstance(exc, OSError):
            code = error_code(exc)
        if stream is not None and before is not None:
            try:
                unchanged(stream, path, before)
            except (OSError, ValueError):
                stage, code, exc = 'verify_unchanged', 'artifact_changed', ValueError('artifact changed during inspection')
        if 'artifact changed' in str(exc):
            code = 'artifact_changed'
        return None, (stage, code, exc)
    finally:
        if stream is not None:
            stream.close()


def selected_inputs(args, report):
    if not args or len(args) > MAX_APKS:
        raise ValueError('provide 1 to {} APK files or one manifest directory'.format(MAX_APKS))
    if any(len(value) > MAX_PATH for value in args):
        raise ValueError('input path exceeds path budget')
    paths = [Path(os.path.abspath(value)) for value in args]
    items = [(path.parent.resolve() / path.name, {}) for path in paths]
    directory = paths[0] if len(paths) == 1 and paths[0].is_dir() else None
    if directory is not None:
        directory = directory.resolve()
        report['input_scope'] = 'manifest_listed_artifacts'
        manifest_path = directory / 'manifest.json'
        with open_regular(manifest_path)[0] as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > MAX_METADATA_BYTES:
                raise ValueError('manifest exceeds metadata budget')
            raw = stream.read(MAX_METADATA_BYTES + 1)
            unchanged(stream, manifest_path, before)
            if len(raw) > MAX_METADATA_BYTES:
                raise ValueError('manifest exceeds metadata budget')
        manifest = json.loads(raw)
        if not isinstance(manifest, dict) or manifest.get('coverage') not in ('complete', 'partial', 'none'):
            raise ValueError('manifest coverage must be complete, partial or none')
        report['source_coverage'] = manifest['coverage']
        artifacts = manifest.get('artifacts')
        if not isinstance(artifacts, list) or len(artifacts) > MAX_APKS:
            raise ValueError('manifest artifacts must be a list of at most {} APKs'.format(MAX_APKS))
        report['selected_artifact_count'] = len(artifacts)
        items = []
        for index, artifact in enumerate(artifacts):
            try:
                if not isinstance(artifact, dict):
                    raise ValueError('artifact must be an object')
                field = 'relative_path' if 'relative_path' in artifact else 'local_path'
                value = artifact.get(field)
                if not isinstance(value, str) or not value or len(value) > MAX_PATH or not valid_entry(value.lstrip('/') if field == 'local_path' else value):
                    raise ValueError('invalid artifact path field')
                path = Path(value)
                if field == 'relative_path' and path.is_absolute():
                    raise ValueError('relative_path must be relative to manifest directory')
                path = directory / path if field == 'relative_path' else Path(os.path.abspath(path))
                check_path(path, directory)
                path = path.parent.resolve() / path.name
                path.relative_to(directory)
                if 'size_bytes' in artifact and (type(artifact['size_bytes']) is not int or artifact['size_bytes'] < 0):
                    raise ValueError('invalid artifact size_bytes')
                if 'sha256' in artifact and (not isinstance(artifact['sha256'], str) or not re.fullmatch(r'[0-9a-fA-F]{64}', artifact['sha256'])):
                    raise ValueError('invalid artifact sha256')
                items.append((path, artifact))
            except (TypeError, ValueError) as exc:
                failure(report, 'artifact[{}]'.format(index), 'manifest', 'invalid_manifest_artifact', exc)
    else:
        report['selected_artifact_count'] = len(items)
    seen, unique = set(), []
    for path, expected in items:
        if path in seen:
            failure(report, str(path), 'select_inputs', 'duplicate_artifact', 'duplicate artifact path')
            continue
        seen.add(path)
        unique.append((path, expected))
    return unique


def main(argv=None):
    report = {**report_metadata('apk-inspect'), 'input_scope': 'provided_inputs',
              'source_coverage': None, 'selected_artifact_count': None,
              'inventory_coverage': 'none', 'coverage': 'none', 'artifacts': [],
              'failures': [], 'limitations': LIMITATIONS,
              'limits': {'apk_count': MAX_APKS, 'file_bytes': MAX_FILE_BYTES,
                         'metadata_bytes': MAX_METADATA_BYTES, 'zip_entries': MAX_ENTRIES,
                         'entry_path_characters': MAX_PATH, 'abis': MAX_ABIS,
                         'displayed_libraries_per_apk': MAX_LIBRARIES}}
    try:
        items = selected_inputs(sys.argv[1:] if argv is None else argv, report)
        seen_files = set()
        for path, expected in items:
            try:
                info = path.lstat()
                key = info.st_dev, info.st_ino
                if key in seen_files:
                    failure(report, str(path), 'select_inputs', 'duplicate_artifact', 'duplicate artifact file identity')
                    continue
                seen_files.add(key)
            except OSError:
                pass
            result, error = inspect(path, expected)
            if error:
                failure(report, str(path), *error)
            else:
                report['artifacts'].append(result)
        if report['artifacts']:
            incomplete = bool(report['failures']) or any(item['libraries_truncated'] for item in report['artifacts'])
            report['inventory_coverage'] = 'partial' if incomplete else 'complete'
            report['coverage'] = 'partial' if incomplete or report['source_coverage'] in ('partial', 'none') else 'complete'
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        failure(report, None, 'select_inputs', 'invalid_input', exc)
    report['finished_at'] = utc_now()
    for error in report['failures']:
        print('error: [stage={} code={}] {}'.format(error['stage'], error['code'], error['error']), file=sys.stderr)
    print(json.dumps(report, ensure_ascii=True))
    return {'complete': 0, 'partial': 1, 'none': 2}[report['coverage']]


if __name__ == '__main__':
    sys.exit(main())
