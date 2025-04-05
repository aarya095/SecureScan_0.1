import datetime
import json
import os
from PyQt6 import QtCore, QtGui, QtWidgets


class QuickScanTab(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi()

    def setupUi(self):

        self.horizontalLayout = QtWidgets.QHBoxLayout(self)
        
        # Left 
        self.home_left_frame = QtWidgets.QFrame(parent=self)
        self.home_left_frame.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        self.home_left_frame.setObjectName("home_left_frame")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.home_left_frame)

        # UI Elements (Assigned Correct Parent)
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

    def update_greeting(self):

            current_hour = datetime.datetime.now().hour

            if 5 <= current_hour <12:
                greeting = "Good Morning!"
            elif 12 <= current_hour <17:
                greeting = "Good Afternoon!"
            elif 17 <= current_hour < 22:
                greeting = "Good Evening!"
            else:
                greeting = "Good Night!"
            
            self.greet_label.setText(greeting)

    def update_security_tip(self):
        json_path = "GUI/tips.json"
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

