# Persistent standalone client, Jython 2.7. JEB Java types stay in this process.
import sys
import os
import json
import codecs
import traceback
from java.io import File
from java.lang import Exception as JavaException
from com.pnfsoftware.jeb.core import JebCoreService
from AOSEyeBridge import AOSEyeBridge


class Context(object):
    def __init__(self, core, engines):
        self.core = core
        self.engines = engines
        self.project = None
        self.input_key = None
        self.project_generation = 0
        self.normalized = None
        self.capabilities = dict(core='verified', engines='verified', standalone_client='verified',
                                 dex='unverified', cfg='unverified', xrefs='unverified',
                                 decompiler='unverified', ast='unverified', ir='not-exported')

    def open(self, path, fingerprint):
        key = (path, fingerprint)
        if self.project is not None and key == self.input_key:
            return
        self.engines.unloadProjects(False)
        self.project = None
        self.input_key = None
        self.normalized = None
        for name in ('dex', 'cfg', 'xrefs', 'decompiler', 'ast'):
            self.capabilities[name] = 'unverified'
        project = self.engines.createProject('AOSEye')
        try:
            if project.processArtifact(File(path)) is None:
                raise RuntimeError('JEB did not return a processed artifact')
        except (Exception, JavaException):
            self.engines.unloadProjects(False)
            raise
        self.project = project
        self.input_key = key
        self.project_generation += 1


def write_response(path, value):
    from PhaseTrace import PhaseTrace
    trace = PhaseTrace(path + '.phases.jsonl') if os.path.exists(path + '.phases.jsonl') else None
    if trace:
        trace.mark('response_serialization_start', response_ok=bool(value.get('ok')))
    temporary = path + '.tmp'
    with codecs.open(temporary, 'w', 'utf-8') as stream:
        json.dump(value, stream, ensure_ascii=True)
    if trace:
        trace.mark('response_serialization_done', response_ok=bool(value.get('ok')), response_bytes=os.path.getsize(temporary))
    os.rename(temporary, path)


def main():
    core = engines = ctx = None
    startup_error = None
    try:
        try:
            core = JebCoreService.getInstance(File(sys.argv[1]))
            engines = core.createEnginesContext()
            ctx = Context(core, engines)
        except (Exception, JavaException):
            startup_error = traceback.format_exc()
        bridge = AOSEyeBridge()
        # stdin carries request-file paths. stdout/stderr are diagnostics only.
        for line in sys.stdin:
            if not line.strip():
                continue
            request_path = json.loads(line)['request']
            with codecs.open(request_path, 'r', 'utf-8') as stream:
                request = json.load(stream)
            response = dict(schema_version=1, request_id=request['request_id'], ok=False)
            try:
                if request['operation'] == 'shutdown':
                    response.update(ok=True)
                elif startup_error:
                    response['error'] = startup_error
                else:
                    response.update(bridge.execute(ctx, request))
                    response['session'] = dict(project_generation=ctx.project_generation,
                                               version=str(core.getVersion()))
                    response['capabilities'] = dict(ctx.capabilities)
            except (Exception, JavaException):
                response['error'] = traceback.format_exc()
            write_response(request['output'], response)
            if request['operation'] == 'shutdown':
                break
    finally:
        try:
            if engines is not None:
                engines.close()
        finally:
            if core is not None:
                core.close()


if __name__ == '__main__':
    main()
