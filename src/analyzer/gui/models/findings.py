from PySide6.QtCore import QAbstractListModel, QModelIndex, Qt


class FindingsModel(QAbstractListModel):
    roles = ['title', 'severity', 'category', 'analysis_level', 'type', 'id', 'verification']

    def __init__(self, parent=None):
        super().__init__(parent)
        self.items = []
        self.visible = []
        self.query = ''
        self.severity = 'ALL'

    def roleNames(self):
        return {Qt.UserRole + n + 1: role.encode() for n, role in enumerate(self.roles)}

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.visible)

    def data(self, index, role=Qt.DisplayRole):
        n = role - Qt.UserRole - 1
        if index.isValid() and 0 <= index.row() < len(self.visible) and 0 <= n < len(self.roles):
            return str(getattr(self.visible[index.row()], self.roles[n]))
        return None

    def reset(self, items=None, query=None, severity=None):
        self.beginResetModel()
        if items is not None:
            self.items = items
        if query is not None:
            self.query = query.casefold()
        if severity is not None:
            self.severity = severity
        self.visible = [f for f in self.items if (self.severity == 'ALL' or f.severity == self.severity)
                        and self.query in (f.title + ' ' + f.category + ' ' + f.location.method).casefold()]
        self.endResetModel()
