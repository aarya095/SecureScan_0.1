import datetime
import json
import os
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtGui import QFont


class QuickScanTab(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi()

    def setupUi(self):
        self.horizontalLayout = QtWidgets.QHBoxLayout(self)

        # Left Frame
        self.home_left_frame = QtWidgets.QFrame(parent=self)
        self.home_left_frame.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        self.verticalLayout = QtWidgets.QVBoxLayout(self.home_left_frame)

        self.greet_label = QtWidgets.QLabel(self.home_left_frame)
        self.greet_label.setObjectName("headerLabel")
        self.update_greeting()

        self.quick_scan_label = QtWidgets.QLabel(self.home_left_frame)
        self.quick_scan_label.setObjectName("headerLabel")
        self.quick_scan_label.setText("Quick Scan")

        self.url_lineEdit = QtWidgets.QLineEdit(self.home_left_frame)
        self.url_lineEdit.setPlaceholderText("Enter URL")

        self.quick_scan_pushButton = QtWidgets.QPushButton(self.home_left_frame)
        self.quick_scan_pushButton.setText("Full Scan")

        self.quick_scan_output_textBrowser = QtWidgets.QTextBrowser(self.home_left_frame)
        self.quick_scan_output_textBrowser.setFont(QFont("Courier New", 12))

        self.verticalLayout.addWidget(self.greet_label)
        self.verticalLayout.addWidget(self.quick_scan_label)
        self.verticalLayout.addWidget(self.url_lineEdit)
        self.verticalLayout.addWidget(self.quick_scan_pushButton)
        self.verticalLayout.addWidget(self.quick_scan_output_textBrowser)

        self.horizontalLayout.addWidget(self.home_left_frame)

        # Right Frame
        self.home_right_frame = QtWidgets.QFrame(self)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.home_right_frame)

        self.top_right_layout = QtWidgets.QHBoxLayout()
        self.top_right_spacer = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)

        from GUI.theme_switch.theme_manager import ThemeSwitcher
        self.theme_toggle_button = ThemeSwitcher(self.home_right_frame)
        self.theme_toggle_button.setFixedSize(40, 40)
        self.top_right_layout.addItem(self.top_right_spacer)
        self.top_right_layout.addWidget(self.theme_toggle_button)

        self.verticalLayout_2.addLayout(self.top_right_layout)

        self.security_tip_label = QtWidgets.QLabel(self.home_right_frame)
        self.security_tip_label.setObjectName("subTitle")
        self.update_security_tip()

        self.num_of_quick_scan_label = QtWidgets.QLabel(self.home_right_frame)
        self.num_of_quick_scan_label.setObjectName("subTitle")
        self.num_of_quick_scan_label.setText("Total No. of Full Scans: <count>")

        self.history_quick_scan_label = QtWidgets.QLabel(self.home_right_frame)
        self.history_quick_scan_label.setObjectName("subTitle")
        self.history_quick_scan_label.setText("History of Full Scans:")

        self.view_full_scan_history_pushButton_2 = QtWidgets.QPushButton(self.home_right_frame)
        self.view_full_scan_history_pushButton_2.setText("View Full Scan History")

        self.scan_history_listWidget = QtWidgets.QListWidget(self.home_right_frame)
        self.scan_history_listWidget.setSpacing(2)
        self.scan_history_listWidget.setStyleSheet("QListWidget { border: 2px; }")
        self.scan_history_listWidget.setMinimumHeight(200)
        self.scan_history_listWidget.setFixedHeight(400)

        self.verticalLayout_2.addWidget(self.security_tip_label)
        self.verticalLayout_2.addWidget(self.num_of_quick_scan_label)
        self.verticalLayout_2.addWidget(self.history_quick_scan_label)
        self.verticalLayout_2.addWidget(self.scan_history_listWidget)
        self.verticalLayout_2.addWidget(self.view_full_scan_history_pushButton_2)

        self.horizontalLayout.addWidget(self.home_right_frame)

    def load_recent_scans(self, scans):
        self.scan_history_listWidget.clear()
        for scan in scans:
            scan_id = scan["scan_id"]
            url = scan["scanned_url"]
            timestamp = scan["scan_timestamp"]

            widget = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout(widget)
            layout.setContentsMargins(5, 5, 5, 5)

            url_label = QtWidgets.QLabel(f"🔗 {url}")
            url_label.setObjectName("subTitle")
            url_label.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)

            time_label = QtWidgets.QLabel(f"🕒 {timestamp}")
            time_label.setStyleSheet("color: gray; font-size: 11px;")

            spacer = QtWidgets.QSpacerItem(30, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)

            pdf_button = QtWidgets.QPushButton("View PDF")
            pdf_button.setObjectName("smallButton")
            pdf_button.setFixedSize(100, 30)
            pdf_button.setProperty("scan_id", scan_id)
            pdf_button.clicked.connect(lambda _, s_id=scan_id: print(f"Generate PDF for scan {s_id}"))  # Placeholder

            layout.addWidget(url_label)
            layout.addWidget(time_label)
            layout.addItem(spacer)
            layout.addWidget(pdf_button)

            list_item = QtWidgets.QListWidgetItem()
            list_item.setSizeHint(widget.sizeHint())
            self.scan_history_listWidget.addItem(list_item)
            self.scan_history_listWidget.setItemWidget(list_item, widget)

    def update_greeting(self):
        current_hour = datetime.datetime.now().hour
        if 5 <= current_hour < 12:
            greeting = "Good Morning!"
        elif 12 <= current_hour < 17:
            greeting = "Good Afternoon!"
        elif 17 <= current_hour < 22:
            greeting = "Good Evening!"
        else:
            greeting = "Good Night!"
        self.greet_label.setText(greeting)

    def update_security_tip(self):
        json_path = "GUI/main_window_ui/tips.json"
        if not os.path.exists(json_path):
            self.security_tip_label.setText("Tip of the Day: Stay safe online!")
            return
        try:
            with open(json_path, "r") as file:
                data = json.load(file)
                tips = data.get("tips", [])
                if tips:
                    today = datetime.datetime.today().day
                    tip_index = today % len(tips)
                    self.security_tip_label.setText(f"Tip of the Day: {tips[tip_index]}")
                else:
                    self.security_tip_label.setText("Tip of the Day: Stay safe online!")
        except Exception as e:
            print(f"Error loading security tips: {e}")
            self.security_tip_label.setText("Tip of the Day: Stay safe online!")


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    window = QtWidgets.QMainWindow()
    quick_scan_tab = QuickScanTab()
    window.setCentralWidget(quick_scan_tab)
    window.setWindowTitle("Security Scanner")
    window.resize(1000, 600)
    mock_scans = [
        {"scan_id": 1, "scanned_url": "http://example.com", "scan_timestamp": "2024-04-07 10:00:00"},
        {"scan_id": 2, "scanned_url": "https://google.com", "scan_timestamp": "2024-04-07 09:45:00"},
    ]
    quick_scan_tab.load_recent_scans(mock_scans)
    window.show()
    sys.exit(app.exec())
