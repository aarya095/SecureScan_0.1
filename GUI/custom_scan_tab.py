from PyQt6 import QtCore, QtWidgets

class CustomScanTab(QtWidgets.QWidget):
    def __init__(self, parent=None, tab_widget=None):
        super().__init__(parent)
        self.tabWidget = tab_widget
        self.setupUi()

    def setupUi(self):
        # Main Layout
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self)
        
        # Left Frame (Custom Scan Section)
        self.custom_scan_left_frame = QtWidgets.QFrame(self)
        self.custom_scan_left_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.custom_scan_left_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.custom_scan_left_frame)

        # Custom Scan Label
        self.custom_scan_label = QtWidgets.QLabel(self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.custom_scan_label)

        # URL Input Field
        self.custom_scan_lineEdit = QtWidgets.QLineEdit(self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.custom_scan_lineEdit)

        # Scan Type ComboBox
        self.custom_scan_selector_comboBox = QtWidgets.QComboBox(self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.custom_scan_selector_comboBox)

        # Custom Scan Button
        self.custom_scan_pushButton = QtWidgets.QPushButton("Start Custom Scan", self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.custom_scan_pushButton)

        # Output Text Browser
        self.custom_scan_output_textBrowser = QtWidgets.QTextBrowser(self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.custom_scan_output_textBrowser)

        # Generate Report Button
        self.generate_custom_scan_report_pushButton = QtWidgets.QPushButton("Generate Detailed Report", self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.generate_custom_scan_report_pushButton)

        # Reset Scanner Button
        self.reset_scanner_pushButton = QtWidgets.QPushButton("Reset Scanners", self.custom_scan_left_frame)
        self.verticalLayout_3.addWidget(self.reset_scanner_pushButton)

        self.horizontalLayout_2.addWidget(self.custom_scan_left_frame)

        # Right Frame (Scan History)
        self.custom_scan_rightframe = QtWidgets.QFrame(self)
        self.custom_scan_rightframe.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.custom_scan_rightframe.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.custom_scan_rightframe)

        # Custom Scan History Labels
        self.num_of_custom_scan_label = QtWidgets.QLabel("Total No. of Custom Scans:", self.custom_scan_rightframe)
        self.verticalLayout_4.addWidget(self.num_of_custom_scan_label)

        self.custom_scan_history_label = QtWidgets.QLabel("History of Custom Scans:", self.custom_scan_rightframe)
        self.verticalLayout_4.addWidget(self.custom_scan_history_label)

        # History Text Browser
        self.custom_scan_history_textBrowser = QtWidgets.QTextBrowser(self.custom_scan_rightframe)
        self.verticalLayout_4.addWidget(self.custom_scan_history_textBrowser)

        # View History Button
        self.view_custom_scan_history_pushButton_2 = QtWidgets.QPushButton("View Custom Scan History", self.custom_scan_rightframe)
        self.verticalLayout_4.addWidget(self.view_custom_scan_history_pushButton_2)

        self.horizontalLayout_2.addWidget(self.custom_scan_rightframe)

        # ✅ Add Tab to Parent Correctly
        if self.tabWidget:
            self.tabWidget.addTab(self, "Custom Scan")
            self.tabWidget.setCurrentWidget(self)  # Ensure the tab is visible

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.custom_scan_label.setText(_translate("MainWindow", "Custom Scan"))
        self.custom_scan_lineEdit.setPlaceholderText(_translate("MainWindow", "Enter URL"))
