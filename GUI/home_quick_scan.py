from PyQt6 import QtCore, QtGui, QtWidgets

class QuickScanTab(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi()

    def setupUi(self):
        # Main Tab Widget
        self.tabWidget = QtWidgets.QTabWidget(self)  # Assigning parent
        self.tabWidget.setGeometry(QtCore.QRect(0, 0, 1221, 771))
        self.tabWidget.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        self.tabWidget.setTabPosition(QtWidgets.QTabWidget.TabPosition.North)  # Changed to North
        self.tabWidget.setObjectName("tabWidget")

        # Home Tab
        self.home_tab = QtWidgets.QWidget()
        self.home_tab.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        self.home_tab.setObjectName("home_tab")

        # Main Layout
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.home_tab)
        
        # Left Frame
        self.home_left_frame = QtWidgets.QFrame(parent=self.home_tab)
        self.home_left_frame.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        self.home_left_frame.setObjectName("home_left_frame")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.home_left_frame)

        # UI Elements (Assigned Correct Parent)
        self.greet_label = QtWidgets.QLabel(self.home_left_frame)
        self.greet_label.setStyleSheet("font-size: 30px; font-weight: bold;")
        self.greet_label.setObjectName("greet_label")

        self.quick_scan_label = QtWidgets.QLabel(self.home_left_frame)
        self.quick_scan_label.setStyleSheet("font-size: 50px; font-weight: bold;")
        self.quick_scan_label.setObjectName("quick_scan_label")

        self.url_lineEdit = QtWidgets.QLineEdit(self.home_left_frame)
        self.url_lineEdit.setPlaceholderText("Enter URL")
        self.url_lineEdit.setStyleSheet("border-radius: 18px; font-size: 25px; padding: 10px;")

        self.quick_scan_pushButton = QtWidgets.QPushButton(self.home_left_frame)
        self.quick_scan_pushButton.setText("Full Scan")
        self.quick_scan_pushButton.setStyleSheet("background-color:rgb(35, 222, 104); color: white; font-size:25px; font-weight:bold;")

        self.quick_scan_output_textBrowser = QtWidgets.QTextBrowser(self.home_left_frame)

        # Add elements to layout
        self.verticalLayout.addWidget(self.greet_label)
        self.verticalLayout.addWidget(self.quick_scan_label)
        self.verticalLayout.addWidget(self.url_lineEdit)
        self.verticalLayout.addWidget(self.quick_scan_pushButton)
        self.verticalLayout.addWidget(self.quick_scan_output_textBrowser)

        self.horizontalLayout.addWidget(self.home_left_frame)

        # Right Frame
        self.home_right_frame = QtWidgets.QFrame(self.home_tab)
        self.home_right_frame.setObjectName("home_right_frame")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.home_right_frame)

        self.security_tip_label = QtWidgets.QLabel(self.home_right_frame)
        self.security_tip_label.setText("Tip of the Day:")
        self.security_tip_label.setStyleSheet("font-size: 20px; font-weight:bold;")

        self.num_of_quick_scan_label = QtWidgets.QLabel(self.home_right_frame)
        self.num_of_quick_scan_label.setText("Total No. of Full Scans:")
        self.num_of_quick_scan_label.setStyleSheet("font-size: 20px; font-weight:bold;")

        self.history_quick_scan_label = QtWidgets.QLabel(self.home_right_frame)
        self.history_quick_scan_label.setText("History of Full Scans:")
        self.history_quick_scan_label.setStyleSheet("font-size: 20px; font-weight:bold;")

        self.view_full_scan_history_pushButton_2 = QtWidgets.QPushButton(self.home_right_frame)
        self.view_full_scan_history_pushButton_2.setText("View Full Scan History")
        self.view_full_scan_history_pushButton_2.setStyleSheet("background-color:rgb(35, 222, 104); color: white; font-size:25px; font-weight:bold;")

        # Add elements to layout
        self.verticalLayout_2.addWidget(self.security_tip_label)
        self.verticalLayout_2.addWidget(self.num_of_quick_scan_label)
        self.verticalLayout_2.addWidget(self.history_quick_scan_label)
        self.verticalLayout_2.addWidget(self.view_full_scan_history_pushButton_2)

        self.horizontalLayout.addWidget(self.home_right_frame)

        # Add Home Tab to Tab Widget
        self.tabWidget.addTab(self.home_tab, "Home")

        # Set main layout
        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.addWidget(self.tabWidget)
        self.setLayout(main_layout)

        # Set Texts
        self.retranslateUi()

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.greet_label.setText(_translate("MainWindow", "Good"))
