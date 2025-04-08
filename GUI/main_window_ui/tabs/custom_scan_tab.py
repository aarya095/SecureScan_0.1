from PyQt6 import QtCore, QtWidgets
from PyQt6.QtCore import QSize, pyqtSignal
from PyQt6.QtGui import QAction, QIcon
from functools import partial

class CustomScanTab(QtWidgets.QWidget):
    pdf_requested = pyqtSignal(str)  # Signal emitted when PDF view is requested

    def __init__(self, parent=None, tab_widget=None):
        super().__init__(parent)
        self.tabWidget = tab_widget
        self.selected_scanners = []
        self.setupUi()

    def setupUi(self):
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self)

        self.custom_scan_left_frame = QtWidgets.QFrame(self)
        self.custom_scan_left_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.custom_scan_left_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.custom_scan_left_frame)

        self.custom_scan_label = QtWidgets.QLabel(self.custom_scan_left_frame)
        self.custom_scan_label.setText("Custom Scan")
        self.verticalLayout_3.addWidget(self.custom_scan_label)

        self.custom_scan_lineEdit = QtWidgets.QLineEdit(self.custom_scan_left_frame)
        self.custom_scan_lineEdit.setPlaceholderText("Enter URL")
        self.verticalLayout_3.addWidget(self.custom_scan_lineEdit)

        self.selector_layout = QtWidgets.QHBoxLayout()

        self.custom_scan_selector_button = QtWidgets.QToolButton(self.custom_scan_left_frame)
        self.custom_scan_selector_button.setText("Select Scanners")
        self.custom_scan_selector_button.setPopupMode(QtWidgets.QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        self.scanner_menu = QtWidgets.QMenu(self)
        self.custom_scan_selector_button.setMenu(self.scanner_menu)
        self.selector_layout.addWidget(self.custom_scan_selector_button)

        # Add spacer between selector and reset icon
        #self.selector_layout.addSpacerItem(QtWidgets.QSpacerItem(20, 0, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum))

        self.reset_icon_button = QtWidgets.QToolButton(self.custom_scan_left_frame)
        self.reset_icon_button.setToolTip("Reset Scanner Selection")
        self.reset_icon_button.setIcon(QIcon("icons/undo.png"))
        self.reset_icon_button.setText("")
        self.reset_icon_button.setIconSize(QSize(48, 48))
        self.reset_icon_button.setFixedSize(54, 54)
        self.reset_icon_button.setStyleSheet("background-color: transparent; border: none;")
        self.reset_icon_button.setObjectName("undoButton")
        self.reset_icon_button.clicked.connect(self.reset_scanner_selection)
        self.selector_layout.addWidget(self.reset_icon_button)

        self.verticalLayout_3.addLayout(self.selector_layout)

        self.scanners = [
            "Http Scanner", "SQL-Injection", "XSS-Injection",
            "Broken Authentication", "CSRF Scanner"
        ]
        self.init_scanner_selection()

        self.custom_scan_pushButton = QtWidgets.QPushButton("Start Custom Scan", self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.custom_scan_pushButton)

        self.custom_scan_output_textBrowser = QtWidgets.QTextBrowser(self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.custom_scan_output_textBrowser)

        self.horizontalLayout_2.addWidget(self.custom_scan_left_frame)

        self.custom_scan_rightframe = QtWidgets.QFrame(self)
        self.custom_scan_rightframe.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.custom_scan_rightframe.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.custom_scan_rightframe)

        self.num_of_custom_scan_label = QtWidgets.QLabel("Total No. of Custom Scans:", self.custom_scan_rightframe)
        self.num_of_custom_scan_label.setObjectName("subTitle")
        self.verticalLayout_4.addWidget(self.num_of_custom_scan_label)

        self.custom_scan_history_label = QtWidgets.QLabel("History of Custom Scans:", self.custom_scan_rightframe)
        self.custom_scan_history_label.setObjectName("subTitle")
        self.verticalLayout_4.addWidget(self.custom_scan_history_label)

        # ✅ Replace text browser with QListWidget
        self.scan_history_listWidget = QtWidgets.QListWidget(self.custom_scan_rightframe)
        self.scan_history_listWidget.setSpacing(2)
        self.scan_history_listWidget.setStyleSheet("QListWidget { border: 2px; }")
        self.scan_history_listWidget.setMinimumHeight(200)
        self.scan_history_listWidget.setFixedHeight(350)
        self.verticalLayout_4.addWidget(self.scan_history_listWidget)

        self.view_custom_scan_history_pushButton_2 = QtWidgets.QPushButton("View Custom Scan History", self.custom_scan_rightframe)
        self.verticalLayout_4.addWidget(self.view_custom_scan_history_pushButton_2)

        self.horizontalLayout_2.addWidget(self.custom_scan_rightframe)

        if self.tabWidget:
            self.tabWidget.addTab(self, "Custom Scan")
            self.tabWidget.setCurrentWidget(self)

    def init_scanner_selection(self):
        """Initialize dropdown menu with checkable scanner options."""
        self.scanner_menu.aboutToHide.connect(self.block_menu_hiding)

        for scanner in self.scanners:
            action = QAction(scanner, self)
            action.setCheckable(True)
            action.toggled.connect(partial(self.toggle_scanner_selection, scanner))
            self.scanner_menu.addAction(action)

    def block_menu_hiding(self):
        """Prevent the menu from closing only while interacting with it."""
        if self.scanner_menu.activeAction():
            QtCore.QTimer.singleShot(100, self.scanner_menu.show)

    def toggle_scanner_selection(self, scanner, checked):
        if checked:
            if scanner not in self.selected_scanners:
                self.selected_scanners.append(scanner)
        else:
            if scanner in self.selected_scanners:
                self.selected_scanners.remove(scanner)

    def reset_scanner_selection(self):
        """Reset all selected scanners."""
        self.selected_scanners.clear()
        for action in self.scanner_menu.actions():
            action.setChecked(False)

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
            time_label.setStyleSheet("color: gray; font-size: 15px;")
            time_label.setMaximumWidth(150)

            spacer = QtWidgets.QSpacerItem(10, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)

            pdf_button = QtWidgets.QPushButton("View PDF")
            pdf_button.setObjectName("smallButton")
            pdf_button.setFixedSize(150, 40)
            pdf_button.setStyleSheet("font-size: 20px;")
            pdf_button.setProperty("scan_id", scan_id)
            pdf_button.clicked.connect(lambda _, s_id=scan_id: self.pdf_requested.emit(s_id))

            layout.addWidget(url_label)
            layout.addWidget(time_label)
            layout.addItem(spacer)
            layout.addWidget(pdf_button)

            list_item = QtWidgets.QListWidgetItem()
            list_item.setSizeHint(widget.sizeHint())
            self.scan_history_listWidget.addItem(list_item)
            self.scan_history_listWidget.setItemWidget(list_item, widget)

    @staticmethod
    def load_stylesheet(file_path):
        try:
            with open(file_path, "r") as f:
                return f.read()
        except FileNotFoundError:
            print(f"Warning: Stylesheet '{file_path}' not found.")
            return ""

if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")

    stylesheet = CustomScanTab.load_stylesheet("GUI/theme_switch/dark_style.qss")
    app.setStyleSheet(stylesheet)
    window = QtWidgets.QMainWindow()
    custom_scan_tab = CustomScanTab()

    # ✅ Example usage of `load_recent_scans` (optional test)
    sample_data = [
        {"scan_id": "001", "scanned_url": "https://example.com", "scan_timestamp": "2025-04-08 13:45"},
        {"scan_id": "002", "scanned_url": "https://testsite.net", "scan_timestamp": "2025-04-08 14:02"},
    ]
    custom_scan_tab.load_recent_scans(sample_data)

    window.setCentralWidget(custom_scan_tab)
    window.setWindowTitle("Custom Scan - Standalone Test")
    window.resize(1100, 650)
    window.show()

    sys.exit(app.exec())
