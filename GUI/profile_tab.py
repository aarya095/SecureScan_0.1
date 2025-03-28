from PyQt6 import QtCore, QtGui, QtWidgets

class ProfileTab(QtWidgets.QTabWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi()

    def setupUi(self):