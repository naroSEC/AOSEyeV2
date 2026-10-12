from pathlib import Path
from PySide6.QtCore import QUrl, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuickControls2 import QQuickStyle
from analyzer.gui.controllers.workspace import Workspace
from analyzer.gui.fonts import configure_fonts


def launch(smoke=False):
    QQuickStyle.setStyle('Basic')
    app = QGuiApplication.instance() or QGuiApplication([])
    configure_fonts()
    app.setOrganizationName('AOSEye')
    app.setApplicationName('AOSEye')
    engine = QQmlApplicationEngine()
    workspace = Workspace()
    engine.rootContext().setContextProperty('workspace', workspace)
    engine.rootContext().setContextProperty('findingsModel', workspace.model)
    engine.load(QUrl.fromLocalFile(str(Path(__file__).parent / 'qml' / 'Main.qml')))
    if not engine.rootObjects():
        return 1
    workspace.section('Overview')
    app.aboutToQuit.connect(workspace.shutdown)
    if smoke:
        QTimer.singleShot(500, app.quit)
    else:
        QTimer.singleShot(0, workspace.checkBackend)
    return app.exec()
