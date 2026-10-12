import os
from pathlib import Path
from PySide6.QtGui import QFontDatabase


def configure_fonts():
    # The Windows offscreen Qt platform does not enumerate system fonts reliably.
    # Register installed fonts; do not copy or distribute font binaries.
    windir = os.environ.get('WINDIR')
    if windir:
        for name in ('segoeui.ttf', 'segoeuib.ttf', 'consola.ttf', 'malgun.ttf'):
            font = Path(windir) / 'Fonts' / name
            if font.exists():
                QFontDatabase.addApplicationFont(str(font))
