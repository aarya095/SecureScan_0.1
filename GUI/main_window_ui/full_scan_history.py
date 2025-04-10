from PyQt6 import QtCore, QtGui, QtWidgets
from datetime import datetime
from PyQt6.QtCore import pyqtSignal, pyqtSlot

class FullScanHistoryWindow(QtWidgets.QMainWindow):
    view_pdf_callback = pyqtSignal(object)

    @pyqtSlot(str)
    def show_error_message(self, msg):
        QtWidgets.QMessageBox.critical(self, "Error", msg)

    def __init__(self):
        super().__init__()
        self.setupUi()

    def setupUi(self):
        self.setObjectName("HistoryWindow")
        self.resize(1099, 693)
        self.setMinimumSize(1099, 693)
        self.setStyleSheet("background-color: #2c3e50;")

        self.centralwidget = QtWidgets.QWidget(parent=self)
        self.setCentralWidget(self.centralwidget)
        self.centralwidget.setObjectName("listwindow")

        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)

        # === Header Frame ===
        self.frame = QtWidgets.QFrame(parent=self.centralwidget)
        self.frame.setStyleSheet("QFrame { border: 2px solid #23DE68; border-radius: 10px; }")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.frame)

        self.custom_scan_history_label = QtWidgets.QLabel("Full Scan History")
        self.custom_scan_history_label.setStyleSheet("color: white; font-size: 30px; font-weight: bold;")
        self.horizontalLayout.addWidget(self.custom_scan_history_label)

        spacerItem = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout.addItem(spacerItem)

        self.delete_history_pushButton = QtWidgets.QPushButton("Delete History")
        self.delete_history_pushButton.setStyleSheet("""
            QPushButton {
                background-color: rgb(35, 222, 104);
                color: white;
                border-radius: 20px;
                font-size: 25px;
                font-weight: bold;
                padding: 10px 30px;
            }
            QPushButton:hover { background-color: #27ae60; }
            QPushButton:pressed { background-color: #1e8449; }
        """)
        self.horizontalLayout.addWidget(self.delete_history_pushButton)
        self.verticalLayout.addWidget(self.frame)

        # === List Frame ===
        self.frame_2 = QtWidgets.QFrame(parent=self.centralwidget)
        self.frame_2.setStyleSheet("QFrame { border: 3px solid #23DE68; border-radius: 10px; }")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.frame_2)

        self.scan_list_widget = QtWidgets.QListWidget(parent=self.frame_2)
        self.scan_list_widget.setStyleSheet("""
            QListWidget {
                background-color: white;
                font-size: 15px;
                color: #2c3e50;
                border: none;
            }
        """)
        self.horizontalLayout_2.addWidget(self.scan_list_widget)
        self.verticalLayout.addWidget(self.frame_2)

    def load_scan_history(self, scan_history):
        self.scan_list_widget.clear()

        def safe_parse_timestamp(ts):
            if isinstance(ts, datetime):
                return ts
            elif isinstance(ts, str):
                return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            else:
                # fallback for invalid types
                return datetime.min  # put invalid timestamps at the beginning

        sorted_history = sorted(scan_history, key=lambda x: safe_parse_timestamp(x["timestamp"]), reverse=True)

        for index, scan in enumerate(sorted_history):
            item_widget = self.create_scan_item_widget(index + 1, scan)
            list_item = QtWidgets.QListWidgetItem(self.scan_list_widget)
            list_item.setSizeHint(item_widget.sizeHint())
            self.scan_list_widget.addItem(list_item)
            self.scan_list_widget.setItemWidget(list_item, item_widget)

    def create_scan_item_widget(self, serial_no, scan):
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(widget)
        layout.setContentsMargins(10, 5, 10, 5)

        # === Serial No Label ===
        serial_label = QtWidgets.QLabel(f"{serial_no}")
        serial_label.setFixedWidth(50)
        serial_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(serial_label)

        # === Scan Info Label ===
        text = (
            f"🕒 {scan['timestamp']}    🌐 {scan['url']}    ⏱ {scan['execution_time']}    🛡 {scan['vulnerabilities_detected']} Vulnerabilities"
        )
        label = QtWidgets.QLabel(text)
        label.setStyleSheet("font-size: 14px;")
        layout.addWidget(label)

        # === View PDF Button ===
        button = QtWidgets.QPushButton("View PDF")
        button.clicked.connect(lambda _, s=scan['id']: self.view_pdf_callback.emit(s))

        button.setStyleSheet("""
            QPushButton {
                background-color: rgb(35, 222, 104);
                color: white;
                border-radius: 10px;
                font-size: 13px;
                font-weight: bold;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
            QPushButton:pressed {
                background-color: #1e8449;
            }
        """)
        layout.addWidget(button)

        return widget

    def view_pdf(self, scan):
        print(f"Opening PDF for scan at {scan['timestamp']}...")

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = FullScanHistoryWindow()
    MainWindow.show()

    # === Sample Data for Testing ===

    scan_history = [
    {'id': 1, 'timestamp': '2025-04-09 12:30:00', 'url': 'http://example.com', 'execution_time': '2 minutes', 'vulnerabilities_detected': 3},
    {'id': 2, 'timestamp': '2025-04-09 14:00:00', 'url': 'http://anotherurl.com', 'execution_time': '5 minutes', 'vulnerabilities_detected': 1},
    {'id': 3, 'timestamp': '2025-04-10 09:00:00', 'url': 'http://newscan.com', 'execution_time': '4 minutes', 'vulnerabilities_detected': 0}
]

    MainWindow.load_scan_history(scan_history)

    sys.exit(app.exec())
