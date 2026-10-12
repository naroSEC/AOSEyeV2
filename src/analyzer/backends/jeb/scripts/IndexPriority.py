"""Stable bounded selection across JEB units; Python 2.7/3 compatible."""
import heapq


def select_priority(items, limit, classes, package_prefix):
    return [row[1] for row in select_global([items], limit, classes, package_prefix)]


def select_global(groups, limit, classes, package_prefix):
    if limit <= 0:
        return []
    exact = set(classes)
    def ranked():
        for unit, items in enumerate(groups):
            for position, item in enumerate(items):
                signature = str(item.getSignature(False))
                owner = signature.split('->', 1)[0]
                rank = 0 if owner in exact else 1 if package_prefix and owner.startswith(package_prefix) else 2
                yield (rank, unit, position, item)
    return [(row[1], row[3]) for row in heapq.nsmallest(limit, ranked())]
