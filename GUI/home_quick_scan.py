from PyQt6 import QtCore, QtGui, QtWidgets
from theme_switch.theme_manager import ThemeSwitcher

class QuickScanTab(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi()

    def setupUi(self):

        # Main Layout
        self.horizontalLayout = QtWidgets.QHBoxLayout(self)
        
        # Left 
        self.home_left_frame = QtWidgets.QFrame(parent=self)
        self.home_left_frame.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        self.home_left_frame.setObjectName("home_left_frame")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.home_left_frame)

        # UI Elements (Assigned Correct Parent)
        self.greet_label = QtWidgets.QLabel(self.home_left_frame)
        self.greet_label.setText("Good")
        self.greet_label.setObjectName("headerLabel")

        self.quick_scan_label = QtWidgets.QLabel(self.home_left_frame)
        self.quick_scan_label.setObjectName("headerLabel")
        self.quick_scan_label.setText("Quick Scan")

        self.url_lineEdit = QtWidgets.QLineEdit(self.home_left_frame)
        self.url_lineEdit.setPlaceholderText("Enter URL")
        
        self.quick_scan_pushButton = QtWidgets.QPushButton(self.home_left_frame)
        self.quick_scan_pushButton.setText("Full Scan")
        
        self.quick_scan_output_textBrowser = QtWidgets.QTextBrowser(self.home_left_frame)

        # Add elements to layout
        self.verticalLayout.addWidget(self.greet_label)
        self.verticalLayout.addWidget(self.quick_scan_label)
        self.verticalLayout.addWidget(self.url_lineEdit)
        self.verticalLayout.addWidget(self.quick_scan_pushButton)
        self.verticalLayout.addWidget(self.quick_scan_output_textBrowser)

        self.horizontalLayout.addWidget(self.home_left_frame)

        # Right Frame
        self.home_right_frame = QtWidgets.QFrame(self)
        self.home_right_frame.setObjectName("home_right_frame")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.home_right_frame)

        self.top_right_layout = QtWidgets.QHBoxLayout()
        
        self.top_right_spacer = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)

        
        self.theme_toggle_button = ThemeSwitcher(self.home_right_frame)
        self.theme_toggle_button.setFixedSize(40, 40)
        self.top_right_layout.addItem(self.top_right_spacer) 
        self.top_right_layout.addWidget(self.theme_toggle_button)

        self.verticalLayout_2.addLayout(self.top_right_layout)


        self.security_tip_label = QtWidgets.QLabel(self.home_right_frame)
        self.security_tip_label.setObjectName("subTitle")
        self.security_tip_label.setText("Tip of the Day:")
        
        self.num_of_quick_scan_label = QtWidgets.QLabel(self.home_right_frame)
        self.num_of_quick_scan_label.setObjectName("subTitle")
        self.num_of_quick_scan_label.setText("Total No. of Full Scans:")
        
        self.history_quick_scan_label = QtWidgets.QLabel(self.home_right_frame)
        self.history_quick_scan_label.setObjectName("subTitle")
        self.history_quick_scan_label.setText("History of Full Scans:")
        
        self.view_full_scan_history_pushButton_2 = QtWidgets.QPushButton(self.home_right_frame)
        self.view_full_scan_history_pushButton_2.setText("View Full Scan History")
        
        # Add elements to layout
        self.verticalLayout_2.addWidget(self.security_tip_label)
        self.verticalLayout_2.addWidget(self.num_of_quick_scan_label)
        self.verticalLayout_2.addWidget(self.history_quick_scan_label)
        self.verticalLayout_2.addWidget(self.view_full_scan_history_pushButton_2)

        self.horizontalLayout.addWidget(self.home_right_frame)

        # Set main layout
        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.addWidget(self)
        self.setLayout(main_layout)

        # Set Texts
        self.retranslateUi()

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
