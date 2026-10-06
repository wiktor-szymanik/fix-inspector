"""Small wrapping toolbar layout for desktop scaling; no widget recreation."""

from PySide6.QtCore import QPoint, QRect, QSize, Qt
from PySide6.QtWidgets import QLayout


class FlowLayout(QLayout):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._items = []
        self.setContentsMargins(0, 0, 0, 0)
        self.setSpacing(8)

    def addItem(self, item):
        self._items.append(item)

    def addWidget(self, widget, *_):
        super().addWidget(widget)

    def addStretch(self, *_):
        pass  # Wrapping toolbars intentionally do not reserve an empty column.

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._arrange(QRect(0, 0, width, 0), measure=True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._arrange(rect, measure=False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self._items:
            if not item.isEmpty():
                size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        return size + QSize(margins.left() + margins.right(), margins.top() + margins.bottom())

    def _arrange(self, rect, *, measure):
        margins = self.contentsMargins()
        inner = rect.adjusted(margins.left(), margins.top(), -margins.right(), -margins.bottom())
        x, y, row_height = inner.x(), inner.y(), 0
        for item in self._items:
            if item.isEmpty():
                continue
            size = item.sizeHint()
            width = min(size.width(), inner.width())
            if x > inner.x() and x + width > inner.right() + 1:
                x, y, row_height = inner.x(), y + row_height + self.spacing(), 0
            height = item.heightForWidth(width) if item.hasHeightForWidth() else size.height()
            if not measure:
                item.setGeometry(QRect(QPoint(x, y), QSize(width, height)))
            x += width + self.spacing()
            row_height = max(row_height, height)
        return y + row_height - rect.y() + margins.bottom()
