"""Measure local synthetic-file hashing; does not read or modify user APKs."""
import json
from pathlib import Path
import statistics
import tempfile
import threading
import time

from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.backends.jeb.backend import file_hash, JebBackend
from analyzer.app.settings import Settings
from analyzer.core.models import Method


def main():
    root = Path(tempfile.mkdtemp(prefix='aoseye-hash-'))
    print(f'Output directory: {root}', flush=True)
    path = root / 'synthetic-128m.bin'
    with path.open('wb') as stream:
        for _ in range(128):
            stream.write(b'x' * (1024 * 1024))
    results = {'bytes': path.stat().st_size, 'single_ms': [], 'double_ms': [], 'cancellation': []}
    for _ in range(3):
        for count, key in ((1, 'single_ms'), (2, 'double_ms')):
            start = time.perf_counter()
            for _ in range(count):
                file_hash(path)
            results[key].append((time.perf_counter() - start) * 1000)
    for _ in range(5):
        token = Cancellation()
        requested = []
        def cancel():
            requested.append(time.perf_counter())
            token.cancel()
        timer = threading.Timer(0.005, cancel)
        start = time.perf_counter()
        timer.start()
        cancelled = False
        try:
            file_hash(path, token)
        except Cancelled:
            cancelled = True
        finished = time.perf_counter()
        timer.cancel()
        timer.join()
        results['cancellation'].append(dict(cancelled=cancelled,
            request_ms=(requested[0] - start) * 1000 if requested else None,
            response_ms=(finished - requested[0]) * 1000 if requested and cancelled else None))
    results['single_median_ms'] = statistics.median(results['single_ms'])
    results['double_median_ms'] = statistics.median(results['double_ms'])
    backend = JebBackend(Settings(jeb_path=str(root / 'no-jeb')))
    backend.input_path = path
    backend.input_sha256 = file_hash(path)
    signature = 'Lsynthetic;->method()V'
    backend.program.methods[signature] = Method(signature, 'Lsynthetic;')
    # Measure actual Python validation path, excluding all JVM/decompiler work.
    backend._run = lambda *args, **kwargs: dict(ast={'nodes': ['synthetic']}, source='synthetic')
    results['validated_ast_ms'] = {}
    for cached in (False, True):
        samples = []
        for _ in range(3):
            backend.program.methods[signature].ast = {'nodes': ['synthetic']} if cached else {}
            start = time.perf_counter()
            backend.get_ast(signature, Cancellation())
            samples.append((time.perf_counter() - start) * 1000)
        results['validated_ast_ms']['cached' if cached else 'uncached'] = samples
    backend.close()
    # Remove only the synthetic file created above; retain measurements.
    path.unlink()
    output = root / 'hashing.json'
    output.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results, indent=2))
    print(f'Report: {output}')


if __name__ == '__main__':
    main()
