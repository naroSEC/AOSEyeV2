"""Bounded, flushed checkpoints; JVM metrics are observations, not allocations."""
import json
import time


class PhaseTrace(object):
    def __init__(self, path, metrics=None):
        self.path = path
        self.count = 0
        self.started = time.time()
        self.metrics = metrics or self.jvm_metrics

    @staticmethod
    def jvm_metrics():
        from java.lang import Runtime
        from java.lang.management import ManagementFactory
        runtime = Runtime.getRuntime()
        return dict(heap_used=runtime.totalMemory() - runtime.freeMemory(),
                    heap_committed=runtime.totalMemory(), heap_max=runtime.maxMemory(),
                    gc_count=sum(max(0, b.getCollectionCount()) for b in ManagementFactory.getGarbageCollectorMXBeans()),
                    gc_millis=sum(max(0, b.getCollectionTime()) for b in ManagementFactory.getGarbageCollectorMXBeans()))

    def mark(self, phase, **counts):
        if self.count >= 256:
            return
        try:
            row = dict(phase=phase, timestamp_epoch_seconds=time.time(), **counts)
            row.update(self.metrics())
            data = json.dumps(row, ensure_ascii=True) + '\n'
            if len(data) > 2048:
                return
            with open(self.path, 'ab') as stream:
                stream.write(data.encode('ascii'))
                stream.flush()
            self.count += 1
        except Exception:
            # Optional diagnostics must not convert a healthy analysis into a failure.
            pass
