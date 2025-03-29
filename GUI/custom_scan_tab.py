from PyQt6 import QtCore, QtWidgets
from PyQt6.QtGui import QAction 
from scanner.run_selected_scanners import CustomSecurityScanner

class CustomScanTab(QtWidgets.QWidget):
    def __init__(self, parent=None, tab_widget=None):
        super().__init__(parent)
        self.tabWidget = tab_widget
        self.selected_scanners = []
        self.security_scanner = CustomSecurityScanner()
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

        self.custom_scan_selector_button = QtWidgets.QToolButton(self.custom_scan_left_frame)
        self.custom_scan_selector_button.setText("Select Scanners ")
        self.custom_scan_selector_button.setPopupMode(QtWidgets.QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        self.scanner_menu = QtWidgets.QMenu(self)
        self.custom_scan_selector_button.setMenu(self.scanner_menu)
        self.verticalLayout_3.addWidget(self.custom_scan_selector_button)

        self.scanners = [
            "Http Scanner", "SQL-Injection", "XSS-Injection",
            "Broken Authentication", "CSRF Scanner"
        ]
        self.init_scanner_selection()

        self.custom_scan_pushButton = QtWidgets.QPushButton("Start Custom Scan", self.custom_scan_left_frame)
        self.custom_scan_pushButton.clicked.connect(self.start_custom_scan)
        self.verticalLayout_3.addWidget(self.custom_scan_pushButton)

        self.custom_scan_output_textBrowser = QtWidgets.QTextBrowser(self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.custom_scan_output_textBrowser)

        self.generate_custom_scan_report_pushButton = QtWidgets.QPushButton("Generate Detailed Report", self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.generate_custom_scan_report_pushButton)

        self.reset_scanner_pushButton = QtWidgets.QPushButton("Reset Scanners", self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.reset_scanner_pushButton)
        self.reset_scanner_pushButton.clicked.connect(self.reset_scanner_selection)

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

        self.custom_scan_history_textBrowser = QtWidgets.QTextBrowser(self.custom_scan_rightframe)
        self.verticalLayout_4.addWidget(self.custom_scan_history_textBrowser)

        self.view_custom_scan_history_pushButton_2 = QtWidgets.QPushButton("View Custom Scan History", self.custom_scan_rightframe)
        self.verticalLayout_4.addWidget(self.view_custom_scan_history_pushButton_2)

        self.horizontalLayout_2.addWidget(self.custom_scan_rightframe)

        if self.tabWidget:
            self.tabWidget.addTab(self, "Custom Scan")
            self.tabWidget.setCurrentWidget(self)  # Ensure the tab is visible

    def init_scanner_selection(self):
        """Initialize dropdown menu with checkable scanner options."""
        self.scanner_menu.aboutToHide.connect(self.block_menu_hiding)

        for scanner in self.scanners:
            action = QAction(scanner, self)
            action.setCheckable(True)

            action.triggered.connect(lambda checked, s=scanner: self.toggle_scanner_selection(s, checked))
            self.scanner_menu.addAction(action)

    def block_menu_hiding(self):
        """Prevent the menu from closing only while interacting with it."""
        if self.scanner_menu.activeAction():  # If an action is hovered or clicked
            QtCore.QTimer.singleShot(100, self.scanner_menu.show)  # Reopen briefly

    def toggle_scanner_selection(self, scanner, checked):
        """Handle scanner selection toggle."""
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

    def start_custom_scan(self):
        """Trigger the scan with selected scanners."""
        url = self.custom_scan_lineEdit.text().strip()
        if not url:
            self.custom_scan_output_textBrowser.append("❌ Please enter a URL.")
            return

        if not self.selected_scanners:
            self.custom_scan_output_textBrowser.append("❌ Please select at least one scanner.")
            return

        self.custom_scan_output_textBrowser.append(f"🔍 Scanning {url} with {', '.join(self.selected_scanners)}...")

        # Call the SecurityScanner class to run the selected scanners
        scan_results = self.security_scanner.run_custom_scan(self.selected_scanners, url)

        # Display results in UI
        for scanner, result in scan_results["scans"].items():
            self.custom_scan_output_textBrowser.append(f"\n🛠️ **{scanner} Results:**\n{result}")

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        
