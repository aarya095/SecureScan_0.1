from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit
import sys

class MyWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Smooth PyQt Resizing")
        self.resize(400, 300)

        layout = QVBoxLayout(self)
        label = QLabel("Smooth Resizing with PyQt")
        entry = QLineEdit()
        
        layout.addWidget(label)
        layout.addWidget(entry)

app = QApplication(sys.argv)
window = MyWindow()
window.show()
sys.exit(app.exec())
