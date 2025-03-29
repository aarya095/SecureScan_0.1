from PyQt6 import QtCore, QtWidgets
from PyQt6.QtGui import QAction 

class CustomScanTab(QtWidgets.QWidget):
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

        self.custom_scan_selector_button = QtWidgets.QToolButton(self.custom_scan_left_frame)
        self.custom_scan_selector_button.setText("Select Scanners ▼")
        self.custom_scan_selector_button.setPopupMode(QtWidgets.QToolButton.ToolButtonPopupMode.InstantPopup)
        self.scanner_menu = QtWidgets.QMenu(self)
        self.custom_scan_selector_button.setMenu(self.scanner_menu)
        self.verticalLayout_3.addWidget(self.custom_scan_selector_button)

        self.scanners = [
            "Http Scanner", "SQL-Injection", "XSS-Injection",
            "Broken Authentication", "CSRF Scanner"
        ]
        self.init_scanner_selection()

        self.custom_scan_pushButton = QtWidgets.QPushButton("Start Custom Scan", self.custom_scan_left_frame)
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
        self.verticalLayout_4.addWidget(self.num_of_custom_scan_label)

        self.custom_scan_history_label = QtWidgets.QLabel("History of Custom Scans:", self.custom_scan_rightframe)
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
        for scanner in self.scanners:
            action = QAction(scanner, self)
            action.setCheckable(True)
            action.triggered.connect(lambda checked, s=scanner: self.toggle_scanner_selection(s, checked))
            self.scanner_menu.addAction(action)

    def toggle_scanner_selection(self, scanner, checked):
        """Handle scanner selection toggle."""
        if checked:
            self.selected_scanners.append(scanner)
        else:
            self.selected_scanners.remove(scanner)
        
        self.update_scanner_button_text()

    def update_scanner_button_text(self):
        """Update dropdown button text based on selected scanners."""
        if self.selected_scanners:
            self.custom_scan_selector_button.setText(", ".join(self.selected_scanners))
        else:
            self.custom_scan_selector_button.setText("Select Scanners ▼")

    def reset_scanner_selection(self):
        """Reset all selected scanners."""
        self.selected_scanners.clear()
        for action in self.scanner_menu.actions():
            action.setChecked(False)
        self.update_scanner_button_text()

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        
