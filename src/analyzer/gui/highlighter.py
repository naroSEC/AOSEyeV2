import re
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor


class CodeHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.patterns = [
            (re.compile(r'\b(?:public|private|protected|class|static|void|return|if|else|new|try|catch|throw|final|import|package|null|true|false)\b'), '#ae99ef'),
            (re.compile(r'"(?:\\.|[^"\\])*"'), '#8ac7aa'),
            (re.compile(r'\b(?:0x[\da-fA-F]+|\d+)\b'), '#e0b780'),
            (re.compile(r'\b(?:invoke-[\w/-]+|move-[\w/-]+|const-[\w/-]+|return-[\w/-]+)\b'), '#81aaff'),
            (re.compile(r'//.*$'), '#71839c'),
        ]

    def highlightBlock(self, text):
        for pattern, color in self.patterns:
            style = QTextCharFormat()
            style.setForeground(QColor(color))
            for match in pattern.finditer(text):
                # Qt positions are UTF-16 code units, not Python Unicode code points.
                start = len(text[:match.start()].encode('utf-16-le')) // 2
                length = len(match.group().encode('utf-16-le')) // 2
                self.setFormat(start, length, style)
