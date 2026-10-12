"""One serialized request channel per persistent JVM; no JEB types escape IPC."""
from __future__ import annotations
import json
import atexit
import logging
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from uuid import uuid4
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.project_manager import write_json
from analyzer.app.settings import Settings
from analyzer.backends.base import BackendError
from analyzer.backends.jeb.protocol import decode_java_text

log = logging.getLogger(__name__)


class JebSession:
    def __init__(self, settings: Settings):
        self.home = Path(settings.jeb_path).resolve() if settings.jeb_path else None
        self.java = settings.java
        self.timeout = settings.timeout_seconds
        self.heap_mib = settings.jvm_heap_mib
        self._active_heap_mib = None
        self.process = None
        self._directory = None
        self._log = None
        self._lock = threading.RLock()
        self.phase_trace = []
        self._phase_path = None

    def _capture_phases(self):
        if self._phase_path is None:
            return
        try:
            rows = []
            with self._phase_path.open('rb') as stream:
                for _ in range(258):
                    line = stream.readline(2049)
                    if not line:
                        break
                    if len(line) > 2048:
                        break
                    try:
                        value = json.loads(line)
                    except ValueError:
                        break
                    if not isinstance(value, dict) or not isinstance(value.get('phase'), str):
                        break
                    rows.append(value)
            self.phase_trace = rows
        except OSError:
            pass

    @property
    def pid(self):
        return self.process.pid if self.process and self.process.poll() is None else None

    def _start(self):
        if self.home is None:
            raise BackendError('JEB path is not configured. Set JEB settings in the GUI, '
                               'pass --jeb-path, or set AOSEYE_JEB_PATH to your licensed installation.')
        if self.process is not None and self.process.poll() is None and self._active_heap_mib == self.heap_mib:
            return
        self._dispose()
        jar = self.home / 'bin/app/jeb.jar'
        if not jar.is_file():
            raise BackendError(f'JEB executable JAR not found: {jar}')
        bundled = self.home / 'bin/runtime/bin/java.exe'
        java_home = Path(os.environ.get('JAVA_HOME', '')) / 'bin/java.exe'
        java = self.java
        if java == 'java':
            if bundled.is_file():
                java = str(bundled)
            elif os.environ.get('JAVA_HOME') and java_home.is_file():
                java = str(java_home)
        runner = Path(__file__).parent / 'scripts/CoreRunner.py'
        command = [java, '-Dfile.encoding=UTF-8', '-Duser.language=en', '-Xmx%sm' % self.heap_mib,
                   '-cp', str(jar.parent / '*'), 'org.python.util.jython', str(runner), str(self.home)]
        self._directory = tempfile.TemporaryDirectory(prefix='aoseye-jeb-')
        self._log = (Path(self._directory.name) / 'process.log').open('wb')
        try:
            self.process = subprocess.Popen(command, cwd=self.home, stdin=subprocess.PIPE,
                stdout=self._log, stderr=subprocess.STDOUT, text=True, encoding='utf-8',
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except OSError as exc:
            self._dispose()
            raise BackendError(f'Could not start Java executable {java!r}; '
                               f'check settings.java, JAVA_HOME and PATH: {exc}') from exc
        except Exception:
            self._dispose()
            raise
        log.info('Started JEB custom-client process pid=%s home=%s', self.process.pid, self.home)
        self._active_heap_mib = self.heap_mib
        atexit.register(self.close)

    def _failure_message(self, message, exit_code=None):
        text = str(message)[-6000:]
        if 'OutOfMemoryError' in text:
            category = 'JVM_OUT_OF_MEMORY_REPORTED'
        elif 'Could not reserve enough space' in text or 'Could not create the Java Virtual Machine' in text:
            category = 'JVM_STARTUP_MEMORY_OR_CONFIGURATION_FAILURE'
        else:
            category = 'JVM_EXIT_OR_OPERATION_FAILURE_UNCLASSIFIED'
        return ('%s; heap_limit_mib=%s; exit_code=%s. Heap is not a process RSS limit; '
                'an unexplained exit does not prove memory exhaustion.\n%s'
                % (category, self._active_heap_mib or self.heap_mib, exit_code, text))

    def _log_tail(self):
        try:
            with (Path(self._directory.name) / 'process.log').open('rb') as stream:
                stream.seek(0, 2)
                stream.seek(max(0, stream.tell() - 6000))
                return stream.read(6000).decode('utf-8', errors='replace')
        except (OSError, AttributeError):
            return 'Process log unavailable'

    def request(self, operation: str, cancel: Cancellation, receive=None, **payload) -> dict:
        while not self._lock.acquire(timeout=0.1):
            cancel.check()
        try:
            cancel.check()
            self._start()
            response = self._exchange(operation, cancel, self.timeout, **payload)
            if 'method_records' in response:
                records = Path(response['method_records']).resolve()
                if records.parent != Path(self._directory.name).resolve() or not records.name.endswith('.response.json.methods.jsonl'):
                    self._dispose()
                    raise BackendError('Invalid method stream path')
                try:
                    if receive is None:
                        raise BackendError('Index response requires a stream consumer')
                    response = receive(response, records)
                finally:
                    records.unlink(missing_ok=True)
            return response
        except (Cancelled, OSError):
            self._dispose()
            raise
        finally:
            self._lock.release()

    def _exchange(self, operation, cancel, timeout, **payload):
        ident = uuid4().hex
        work = Path(self._directory.name)
        request = work / (ident + '.request.json')
        output = work / (ident + '.response.json')
        if operation == 'index':
            self.phase_trace = []
            self._phase_path = Path(str(output) + '.phases.jsonl')
        write_json(request, dict(schema_version=1, request_id=ident, operation=operation,
                                 output=str(output), **payload))
        try:
            try:
                self.process.stdin.write(json.dumps({'request': str(request)}) + '\n')
                self.process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                message = self._failure_message(self._log_tail(), self.process.poll())
                self._dispose()
                raise BackendError('JEB request channel failed: ' + message) from exc
            deadline = time.monotonic() + timeout
            while not output.exists():
                cancel.check()
                if self.process.poll() is not None:
                    message = self._failure_message(self._log_tail(), self.process.returncode)
                    self._dispose()
                    raise BackendError('JEB bridge exited without a response: ' + message)
                if time.monotonic() >= deadline:
                    self._dispose()
                    raise BackendError('JEB operation timed out; session terminated')
                cancel.event.wait(0.05)
            cancel.check()
            try:
                response = json.loads(output.read_text(encoding='utf-8'), object_hook=decode_java_text)
            except (ValueError, OSError) as exc:
                self._dispose()
                raise BackendError('Invalid JEB bridge JSON response') from exc
            if response.get('schema_version') != 1 or response.get('request_id') != ident:
                self._dispose()
                raise BackendError('Invalid JEB bridge protocol / request ID')
            if not response.get('ok'):
                error = response.get('error', 'JEB operation failed')
                message = self._failure_message(error)
                if 'OutOfMemoryError' in str(error):
                    self._dispose()
                raise BackendError(message)
            return response
        finally:
            if operation == 'index':
                self._capture_phases()
                if self._phase_path is not None:
                    self._phase_path.unlink(missing_ok=True)
            request.unlink(missing_ok=True)
            output.unlink(missing_ok=True)

    def close(self):
        with self._lock:
            try:
                if self.process is not None and self.process.poll() is None:
                    self._exchange('shutdown', Cancellation(), 5)
                    self.process.wait(timeout=5)
            except (BackendError, OSError, subprocess.TimeoutExpired):
                log.warning('JEB session did not shut down gracefully; terminating it')
            finally:
                self._dispose()

    def _dispose(self):
        self._capture_phases()
        self._active_heap_mib = None
        atexit.unregister(self.close)
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            if self.process.stdin is not None:
                self.process.stdin.close()
            self.process = None
        if self._log is not None:
            self._log.close()
            self._log = None
        if self._directory is not None:
            self._directory.cleanup()
            self._directory = None
