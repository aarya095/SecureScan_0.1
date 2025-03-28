from PyQt6 import QtCore, QtGui, QtWidgets

class ProfileTab(QtWidgets.QWidget):
    def __init__(self, parent=None, tab_widget=None):
        super().__init__(parent)
        self.tabWidget = tab_widget
        self.setupUi()

    def setupUi(self):
        # Profile Tab
        self.setObjectName("profile_tab")

        self.horizontalLayout_4 = QtWidgets.QHBoxLayout(self)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")

        # Left Frame
        self.profile_tab_left_frame = QtWidgets.QFrame(parent=self)
        self.profile_tab_left_frame.setSizePolicy(
            QtWidgets.QSizePolicy(
                QtWidgets.QSizePolicy.Policy.Expanding,
                QtWidgets.QSizePolicy.Policy.Expanding,
            )
        )
        self.profile_tab_left_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.profile_tab_left_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.profile_tab_left_frame.setObjectName("profile_tab_left_frame")

        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.profile_tab_left_frame)
        self.verticalLayout_7.setObjectName("verticalLayout_7")

        # Labels
        self.username_label = QtWidgets.QLabel(parent=self.profile_tab_left_frame)
        self.username_label.setStyleSheet("color:black; font-size: 20px; font-weight:bold;")
        self.username_label.setObjectName("username_label")
        self.verticalLayout_7.addWidget(self.username_label)

        self.email_label = QtWidgets.QLabel(parent=self.profile_tab_left_frame)
        self.email_label.setStyleSheet("color:black; font-size: 20px; font-weight:bold;")
        self.email_label.setObjectName("email_label")
        self.verticalLayout_7.addWidget(self.email_label)

        self.time_date_acc_created_label = QtWidgets.QLabel(parent=self.profile_tab_left_frame)
        self.time_date_acc_created_label.setStyleSheet("color:black; font-size: 20px; font-weight:bold;")
        self.time_date_acc_created_label.setObjectName("time_date_acc_created_label")
        self.verticalLayout_7.addWidget(self.time_date_acc_created_label)

        self.last_login_date_time_label = QtWidgets.QLabel(parent=self.profile_tab_left_frame)
        self.last_login_date_time_label.setStyleSheet("color:black; font-size: 20px; font-weight:bold;")
        self.last_login_date_time_label.setObjectName("last_login_date_time_label")
        self.verticalLayout_7.addWidget(self.last_login_date_time_label)

        # Buttons
        self.log_out_pushButton = QtWidgets.QPushButton(parent=self.profile_tab_left_frame)
        self.log_out_pushButton.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed))
        self.log_out_pushButton.setStyleSheet("""
            QPushButton {
                background-color:rgb(35, 222, 104);
                color: white;
                border-radius: 20px;
                font-size:25px;
                font-weight:bold;
                padding: 10px 30px;
            }
            QPushButton:hover { background-color: #27ae60; }
            QPushButton:pressed { background-color: #1e8449; transform: scale(0.95); }
        """)
        self.log_out_pushButton.setObjectName("log_out_pushButton")
        self.verticalLayout_7.addWidget(self.log_out_pushButton)

        self.delete_account_pushButton = QtWidgets.QPushButton(parent=self.profile_tab_left_frame)
        self.delete_account_pushButton.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed))
        self.delete_account_pushButton.setStyleSheet("""
            QPushButton {
                background-color:rgb(35, 222, 104);
                color: white;
                border-radius: 20px;
                font-size:25px;
                font-weight:bold;
                padding: 10px 30px;
            }
            QPushButton:hover { background-color: #27ae60; }
            QPushButton:pressed { background-color: #1e8449; transform: scale(0.95); }
        """)
        self.delete_account_pushButton.setObjectName("delete_account_pushButton")
        self.verticalLayout_7.addWidget(self.delete_account_pushButton)

        self.horizontalLayout_4.addWidget(self.profile_tab_left_frame)

        # ✅ FIXED: Replaced `self.profile_tab` with `self`
        self.profile_tab_right_frame = QtWidgets.QFrame(parent=self)
        self.profile_tab_right_frame.setSizePolicy(
            QtWidgets.QSizePolicy(
                QtWidgets.QSizePolicy.Policy.Expanding,
                QtWidgets.QSizePolicy.Policy.Expanding,
            )
        )
        self.profile_tab_right_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.profile_tab_right_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.profile_tab_right_frame.setObjectName("profile_tab_right_frame")

        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.profile_tab_right_frame)
        self.verticalLayout_8.setObjectName("verticalLayout_8")

        # Right Panel Labels
        self.num_of_full_scan_label = QtWidgets.QLabel(parent=self.profile_tab_right_frame)
        self.num_of_full_scan_label.setStyleSheet("color:black; font-size: 20px; font-weight:bold;")
        self.num_of_full_scan_label.setObjectName("num_of_full_scan_label")
        self.verticalLayout_8.addWidget(self.num_of_full_scan_label)

        self.num_of_custom_scan_label_2 = QtWidgets.QLabel(parent=self.profile_tab_right_frame)
        self.num_of_custom_scan_label_2.setStyleSheet("color:black; font-size: 20px; font-weight:bold;")
        self.num_of_custom_scan_label_2.setObjectName("num_of_custom_scan_label_2")
        self.verticalLayout_8.addWidget(self.num_of_custom_scan_label_2)

        self.num_of_total_scan_label = QtWidgets.QLabel(parent=self.profile_tab_right_frame)
        self.num_of_total_scan_label.setStyleSheet("color:black; font-size: 20px; font-weight:bold;")
        self.num_of_total_scan_label.setObjectName("num_of_total_scan_label")
        self.verticalLayout_8.addWidget(self.num_of_total_scan_label)

        self.num_of_total_vulnerabilities_label = QtWidgets.QLabel(parent=self.profile_tab_right_frame)
        self.num_of_total_vulnerabilities_label.setStyleSheet("color:black; font-size: 20px; font-weight:bold;")
        self.num_of_total_vulnerabilities_label.setObjectName("num_of_total_vulnerabilities_label")
        self.verticalLayout_8.addWidget(self.num_of_total_vulnerabilities_label)

        self.vulnerabilities_pie_chart_graphicsView = QtWidgets.QGraphicsView(parent=self.profile_tab_right_frame)
        self.vulnerabilities_pie_chart_graphicsView.setObjectName("vulnerabilities_pie_chart_graphicsView")
        self.verticalLayout_8.addWidget(self.vulnerabilities_pie_chart_graphicsView)

        self.terms_and_conditions_commandLinkButton = QtWidgets.QCommandLinkButton(parent=self.profile_tab_right_frame)
        self.terms_and_conditions_commandLinkButton.setStyleSheet("""
            QCommandLinkButton {
                color: black;
                qproperty-icon: none;
                font-size: 16px;
                font-weight:bold;
                text-decoration: underline;
            }
        """)
        self.terms_and_conditions_commandLinkButton.setObjectName("terms_and_conditions_commandLinkButton")
        self.verticalLayout_8.addWidget(self.terms_and_conditions_commandLinkButton)

        self.horizontalLayout_4.addWidget(self.profile_tab_right_frame)
        self.retranslateUi(None)
        

        # ✅ FIXED: Ensure the tab is added to `tabWidget` properly
        if self.tabWidget:
            self.tabWidget.addTab(self, "Profile")

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        self.username_label.setText(_translate("MainWindow", "Userrname:"))
        self.email_label.setText(_translate("MainWindow", "Email:"))
        self.time_date_acc_created_label.setText(_translate("MainWindow", "Time and Date of last login:"))
        self.last_login_date_time_label.setText(_translate("MainWindow", "Account created at"))
        self.log_out_pushButton.setText(_translate("MainWindow", "Log Out"))
        self.delete_account_pushButton.setText(_translate("MainWindow", "Delete Account"))
        self.num_of_full_scan_label.setText(_translate("MainWindow", "No. of full scans:"))
        self.num_of_custom_scan_label_2.setText(_translate("MainWindow", "No. of custom scans:"))
        self.num_of_total_scan_label.setText(_translate("MainWindow", "Total no. of vulnerabilities found:"))
        self.num_of_total_vulnerabilities_label.setText(_translate("MainWindow", "Pie chart for percentage of each vulnerability"))
        self.terms_and_conditions_commandLinkButton.setText(_translate("MainWindow", "terms and conditions"))
