#!/usr/bin/env python3
"""Project automation scripts."""

import cProfile
import io
import os
import pstats
import shutil
import subprocess
import sys
import time
from pathlib import Path

GENERATED_PATHS = (
    '.coverage',
    '.pytest_cache',
    '.ruff_cache',
    'htmlcov',
    '__pycache__',
    'gcid/__pycache__',
    'tests/__pycache__',
)


def run_cmd(cmd: list[str]) -> int:
    """Run command and return exit code."""
    return subprocess.run(cmd, cwd=Path.cwd()).returncode


def remove_generated_artifacts() -> None:
    """Remove local artifacts created by test and import runs."""
    root = Path.cwd()
    for path_text in GENERATED_PATHS:
        path = root / path_text
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def clean() -> None:
    """Clean generated local artifacts."""
    remove_generated_artifacts()


def test() -> None:
    """Run tests with coverage."""
    exit_code = run_cmd(
        [
            'pytest',
            '--cov=gcid',
            '--cov-report=term-missing',
            '--cov-report=html',
        ]
    )
    sys.exit(exit_code)


def lint() -> None:
    """Run linting checks."""
    exit_code = run_cmd(['ruff', 'check', '.'])
    sys.exit(exit_code)


def format() -> None:
    """Format code and fix linting issues."""
    format_code = run_cmd(['ruff', 'format', '.'])
    fix_code = run_cmd(['ruff', 'check', '--fix', '.'])
    sys.exit(max(format_code, fix_code))


def check() -> None:
    """Run the official clean validation workflow."""
    remove_generated_artifacts()
    lint_code = run_cmd(['ruff', 'check', '.'])
    test_code = run_cmd(
        [
            'pytest',
            '--cov=gcid',
            '--cov-report=term-missing',
            '--cov-report=html',
        ]
    )
    remove_generated_artifacts()
    sys.exit(max(lint_code, test_code))


def _time_ops(label: str, count: int, callback) -> tuple[float, float]:
    start = time.perf_counter()
    callback()
    elapsed = time.perf_counter() - start
    us_per_op = elapsed / count * 1_000_000
    ops_per_sec = count / elapsed
    print(f'{label:28} {us_per_op:10.3f} us/op {ops_per_sec:12,.0f} ops/s')
    return us_per_op, ops_per_sec


def _run_profile(callback) -> None:
    profiler = cProfile.Profile()
    profiler.enable()
    callback()
    profiler.disable()

    output = io.StringIO()
    stats = pstats.Stats(profiler, stream=output).strip_dirs()
    stats.sort_stats('cumtime').print_stats(20)
    print()
    print('cProfile top cumulative functions')
    print('-' * 64)
    print(output.getvalue())


def benchmark() -> None:
    """Benchmark GCID conversion costs."""
    import hashlib
    import hmac

    import base58
    from cryptography.hazmat.primitives.ciphers import (
        Cipher,
        algorithms,
        modes,
    )
    from pydantic import BaseModel

    from gcid import registry
    from gcid.gcid import IdType, id_to_seq, seq_to_id

    count = int(os.environ.get('GCID_BENCH_N', '100000'))
    seqs = list(range(1, count + 1))
    ids = registry(profile='prf', asset='asset')
    profile_api_ids = [seq_to_id(IdType.PROFILE, seq) for seq in seqs]
    asset_api_ids = [seq_to_id(IdType.ASSET, seq) for seq in seqs]
    typed_profile_ids = [ids.profile.from_seq(seq) for seq in seqs]

    legacy_key = b'X' * 32
    legacy_hmac_key = b'test'
    legacy_header = b'\01' + (b'\00' * 7)
    legacy_cipher = Cipher(algorithms.AES(legacy_key), modes.CBC(b'\00' * 16))
    legacy_hmac_base = hashlib.blake2b(
        digest_size=16, key=legacy_hmac_key, person=b'id'
    )

    def legacy_digest(encrypted: bytes) -> bytes:
        digest = legacy_hmac_base.copy()
        digest.update(encrypted)
        return digest.digest()[:4]

    def legacy_seq_to_id(prefix: str, seq: int) -> str:
        encryptor = legacy_cipher.encryptor()
        encrypted = encryptor.update(legacy_header + seq.to_bytes(8, 'big'))
        payload = base58.b58encode(encrypted + legacy_digest(encrypted))
        return f'{prefix}_{payload.decode("ascii")}'

    def legacy_id_to_seq(api_id: str, expected_prefix: str) -> int:
        prefix, encoded_payload = api_id.split('_', 1)
        if prefix != expected_prefix:
            raise ValueError('invalid prefix')

        decoded = base58.b58decode(encoded_payload)
        encrypted = decoded[:16]
        tag = decoded[16:]
        if not hmac.compare_digest(tag, legacy_digest(encrypted)):
            raise ValueError('invalid tag')

        decryptor = legacy_cipher.decryptor()
        plaintext = decryptor.update(encrypted)
        if plaintext[0] != 1:
            raise ValueError('invalid version')
        return int.from_bytes(plaintext[8:], 'big')

    legacy_profile_api_ids = [legacy_seq_to_id('prf', seq) for seq in seqs]
    encoded_payloads = [
        api_id.split('_', maxsplit=1)[1].encode('utf-8')
        for api_id in profile_api_ids
    ]
    decoded_payloads = [
        base58.b58decode(encoded_payload)
        for encoded_payload in encoded_payloads
    ]

    class Asset(BaseModel):
        id: ids.asset
        owner_id: ids.profile

    scenarios = [
        (
            'v2 seq_to_id',
            lambda: [seq_to_id(IdType.PROFILE, seq) for seq in seqs],
        ),
        (
            'v2 id_to_seq',
            lambda: [
                id_to_seq(api_id, IdType.PROFILE) for api_id in profile_api_ids
            ],
        ),
        (
            'v1 seq_to_id',
            lambda: [legacy_seq_to_id('prf', seq) for seq in seqs],
        ),
        (
            'v1 id_to_seq',
            lambda: [
                legacy_id_to_seq(api_id, 'prf')
                for api_id in legacy_profile_api_ids
            ],
        ),
        (
            'typed id from seq',
            lambda: [ids.profile.from_seq(seq) for seq in seqs],
        ),
        (
            'typed id .seq cached',
            lambda: [api_id.seq for api_id in typed_profile_ids],
        ),
        (
            'pydantic string validate',
            lambda: [
                Asset(id=asset_api_ids[index], owner_id=profile_api_ids[index])
                for index in range(count)
            ],
        ),
        (
            'pydantic typed validate',
            lambda: [
                Asset(
                    id=ids.asset.from_seq(seq),
                    owner_id=typed_profile_ids[index],
                )
                for index, seq in enumerate(seqs)
            ],
        ),
        (
            'base58 encode only',
            lambda: [
                base58.b58encode(decoded_payload)
                for decoded_payload in decoded_payloads
            ],
        ),
        (
            'base58 decode only',
            lambda: [
                base58.b58decode(encoded_payload)
                for encoded_payload in encoded_payloads
            ],
        ),
    ]

    print(f'GCID conversion benchmark ({count:,} operations)')
    print('-' * 64)

    for label, callback in scenarios:
        _time_ops(label, count, callback)

    if os.environ.get('GCID_BENCH_PROFILE') == '1':

        def workload() -> None:
            for _, callback in scenarios[0:6]:
                callback()

        _run_profile(workload)
