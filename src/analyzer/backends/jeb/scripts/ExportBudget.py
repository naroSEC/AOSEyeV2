"""Python 2.7/3 compatible ASCII JSONL byte accounting for method exports."""
import json


class ExportBudget(object):
    def __init__(self, limit):
        if isinstance(limit, bool) or not isinstance(limit, (int,)) or limit <= 0:
            raise ValueError('Invalid method export byte budget')
        self.limit = limit
        self.used = 0
        self.exhausted = False
        self.skipped = 0

    def record(self, value):
        if self.exhausted:
            self.skipped += 1
            return None
        record = json.dumps(value, ensure_ascii=True) + '\n'
        if len(record) > self.limit - self.used:
            self.exhausted = True
            self.skipped += 1
            return None
        self.used += len(record)
        return record
