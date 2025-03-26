from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QFrame
from PyQt6.QtCore import Qt
import sys

class CenteredFrameApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Centered Frame Example")
        self.setGeometry(100, 100, 800, 600)  # Initial size
        self.setMinimumSize(600, 400)  # Prevents shrinking too much

        # Create a central widget (acts as a wrapper)
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        # Create a main layout for the central widget
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)  # Removes extra margins

        # Create a frame that holds UI elements
        self.center_frame = QFrame(self)
        self.center_frame.setStyleSheet("background-color: #2E3B4E; border-radius: 10px;")
        self.center_frame.setFixedSize(500, 300)  # Fixed size for content area

        # Add the frame to the layout and center it
        layout.addStretch()  # Push content downward
        layout.addWidget(self.center_frame, alignment=Qt.AlignmentFlag.AlignCenter)  # Align Center
        layout.addStretch()  # Push content upward

app = QApplication(sys.argv)
window = CenteredFrameApp()
window.show()
sys.exit(app.exec())
