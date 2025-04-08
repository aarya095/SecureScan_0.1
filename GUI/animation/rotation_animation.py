from PyQt6.QtWidgets import QPushButton
from PyQt6.QtCore import QPropertyAnimation, pyqtProperty, QSize
from PyQt6.QtGui import QPainter, QTransform

class RotatingButton(QPushButton):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rotation = 0

    def setRotation(self, value):
        self._rotation = value
        self.update()

    def getRotation(self):
        return self._rotation

    rotation = pyqtProperty(float, fget=getRotation, fset=setRotation)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        icon = self.icon()
        if icon:
            size = self.iconSize()
            pixmap = icon.pixmap(size)
            transform = QTransform()
            transform.translate(self.width() / 2, self.height() / 2)
            transform.rotate(self._rotation)
            transform.translate(-size.width() / 2, -size.height() / 2)
            painter.setTransform(transform)
            painter.drawPixmap(0, 0, pixmap)
        else:
            super().paintEvent(event)
