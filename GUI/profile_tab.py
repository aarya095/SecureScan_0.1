from PyQt6 import QtCore, QtGui, QtWidgets

class ProfileTab(QtWidgets.QTabWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi()

    def setupUi(self):
        #Profile Tab
        self.profile_tab.setObjectName("profile_tab")
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout(self.profile_tab)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.profile_tab_left_frame = QtWidgets.QFrame(parent=self.profile_tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.profile_tab_left_frame.sizePolicy().hasHeightForWidth())
        self.profile_tab_left_frame.setSizePolicy(sizePolicy)
        self.profile_tab_left_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.profile_tab_left_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.profile_tab_left_frame.setObjectName("profile_tab_left_frame")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.profile_tab_left_frame)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.username_label = QtWidgets.QLabel(parent=self.profile_tab_left_frame)
        self.username_label.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 20px;\n"
"    font-weight:bold;\n"
"}")
        self.username_label.setObjectName("username_label")
        self.verticalLayout_7.addWidget(self.username_label)
        self.email_label = QtWidgets.QLabel(parent=self.profile_tab_left_frame)
        self.email_label.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 20px;\n"
"    font-weight:bold;\n"
"}")
        self.email_label.setObjectName("email_label")
        self.verticalLayout_7.addWidget(self.email_label)
        self.time_date_acc_created_label = QtWidgets.QLabel(parent=self.profile_tab_left_frame)
        self.time_date_acc_created_label.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 20px;\n"
"    font-weight:bold;\n"
"}")
        self.time_date_acc_created_label.setObjectName("time_date_acc_created_label")
        self.verticalLayout_7.addWidget(self.time_date_acc_created_label)
        self.last_login_date_time_label = QtWidgets.QLabel(parent=self.profile_tab_left_frame)
        self.last_login_date_time_label.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 20px;\n"
"    font-weight:bold;\n"
"}")
        self.last_login_date_time_label.setObjectName("last_login_date_time_label")
        self.verticalLayout_7.addWidget(self.last_login_date_time_label)
        self.log_out_pushButton = QtWidgets.QPushButton(parent=self.profile_tab_left_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.log_out_pushButton.sizePolicy().hasHeightForWidth())
        self.log_out_pushButton.setSizePolicy(sizePolicy)
        self.log_out_pushButton.setStyleSheet("QPushButton {\n"
"    background-color:rgb(35, 222, 104);\n"
"    color: white;\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.1px;\n"
"    transition: all 0.2s ease;\n"
"    font-size:25px;\n"
"    font-weight:bold;\n"
"    padding: 10px 5px;\n"
"    padding-right: 30px;\n"
"    padding-left: 30px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: #27ae60;  /* Darker green */\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"    background-color: #1e8449;\n"
"    transform: scale(0.95);  /* Slight shrink effect */\n"
"}")
        self.log_out_pushButton.setObjectName("log_out_pushButton")
        self.verticalLayout_7.addWidget(self.log_out_pushButton)
        self.delete_account_pushButton = QtWidgets.QPushButton(parent=self.profile_tab_left_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.delete_account_pushButton.sizePolicy().hasHeightForWidth())
        self.delete_account_pushButton.setSizePolicy(sizePolicy)
        self.delete_account_pushButton.setStyleSheet("QPushButton {\n"
"    background-color:rgb(35, 222, 104);\n"
"    color: white;\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.1px;\n"
"    transition: all 0.2s ease;\n"
"    font-size:25px;\n"
"    font-weight:bold;\n"
"    padding: 10px 5px;\n"
"    padding-right: 30px;\n"
"    padding-left: 30px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: #27ae60;  /* Darker green */\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"    background-color: #1e8449;\n"
"    transform: scale(0.95);  /* Slight shrink effect */\n"
"}")
        self.delete_account_pushButton.setObjectName("delete_account_pushButton")
        self.verticalLayout_7.addWidget(self.delete_account_pushButton)
        self.horizontalLayout_4.addWidget(self.profile_tab_left_frame)
        self.profile_tab_right_frame = QtWidgets.QFrame(parent=self.profile_tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.profile_tab_right_frame.sizePolicy().hasHeightForWidth())
        self.profile_tab_right_frame.setSizePolicy(sizePolicy)
        self.profile_tab_right_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.profile_tab_right_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.profile_tab_right_frame.setObjectName("profile_tab_right_frame")
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.profile_tab_right_frame)
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.num_of_full_scan_label = QtWidgets.QLabel(parent=self.profile_tab_right_frame)
        self.num_of_full_scan_label.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 20px;\n"
"    font-weight:bold;\n"
"}")
        self.num_of_full_scan_label.setObjectName("num_of_full_scan_label")
        self.verticalLayout_8.addWidget(self.num_of_full_scan_label)
        self.num_of_custom_scan_label_2 = QtWidgets.QLabel(parent=self.profile_tab_right_frame)
        self.num_of_custom_scan_label_2.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 20px;\n"
"    font-weight:bold;\n"
"}")
        self.num_of_custom_scan_label_2.setObjectName("num_of_custom_scan_label_2")
        self.verticalLayout_8.addWidget(self.num_of_custom_scan_label_2)
        self.num_of_total_scan_label = QtWidgets.QLabel(parent=self.profile_tab_right_frame)
        self.num_of_total_scan_label.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 20px;\n"
"    font-weight:bold;\n"
"}")
        self.num_of_total_scan_label.setObjectName("num_of_total_scan_label")
        self.verticalLayout_8.addWidget(self.num_of_total_scan_label)
        self.num_of_total_vulnerabilities_label = QtWidgets.QLabel(parent=self.profile_tab_right_frame)
        self.num_of_total_vulnerabilities_label.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 20px;\n"
"    font-weight:bold;\n"
"}")
        self.num_of_total_vulnerabilities_label.setObjectName("num_of_total_vulnerabilities_label")
        self.verticalLayout_8.addWidget(self.num_of_total_vulnerabilities_label)
        self.vulnerabilties_pie_chart_graphicsView = QtWidgets.QGraphicsView(parent=self.profile_tab_right_frame)
        self.vulnerabilties_pie_chart_graphicsView.setObjectName("vulnerabilties_pie_chart_graphicsView")
        self.verticalLayout_8.addWidget(self.vulnerabilties_pie_chart_graphicsView)
        self.terms_and_conditions_commandLinkButton = QtWidgets.QCommandLinkButton(parent=self.profile_tab_right_frame)
        self.terms_and_conditions_commandLinkButton.setStyleSheet("QCommandLinkButton {\n"
"    color: black;\n"
"    qproperty-icon: none;\n"
"    font: Nirmala text;\n"
"    font-size: 16px;\n"
"    font-weight:bold;\n"
"    text-decoration: underline;\n"
"    background-color: rgba(255, 255, 255, 0);\n"
"}")
        self.terms_and_conditions_commandLinkButton.setObjectName("terms_and_conditions_commandLinkButton")
        self.verticalLayout_8.addWidget(self.terms_and_conditions_commandLinkButton)
        self.horizontalLayout_4.addWidget(self.profile_tab_right_frame)
        self.tabWidget.addTab(self.profile_tab, "")
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(4)
        self.custom_scan_selector_comboBox.setCurrentIndex(0)
        self.clear_history_comboBox.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.greet_label.setText(_translate("MainWindow", "Good"))
        self.quick_scan_label.setText(_translate("MainWindow", "Quick Scan"))
        self.url_lineEdit.setPlaceholderText(_translate("MainWindow", "enter url"))
        self.quick_scan_pushButton.setText(_translate("MainWindow", "Full Scan"))
        self.generate_full_scan_report_pushButton.setText(_translate("MainWindow", "Generate Detailed Report"))
        self.security_tip_label.setText(_translate("MainWindow", "Tip of the Day:"))
        self.num_of_quick_scan_label.setText(_translate("MainWindow", "Total No. of full scans:"))
        self.history_quick_scan_label.setText(_translate("MainWindow", "History of full scans:"))
        self.view_full_scan_history_pushButton_2.setText(_translate("MainWindow", "View Full Scan History"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.home_tab), _translate("MainWindow", "Home"))
        self.custom_scan_label.setText(_translate("MainWindow", "Custom Scan"))
        self.custom_scan_lineEdit.setPlaceholderText(_translate("MainWindow", "enter url"))
        self.custom_scan_selector_comboBox.setCurrentText(_translate("MainWindow", "http scan"))
        self.custom_scan_selector_comboBox.setItemText(0, _translate("MainWindow", "http scan"))
        self.custom_scan_selector_comboBox.setItemText(1, _translate("MainWindow", "sql-injection"))
        self.custom_scan_selector_comboBox.setItemText(2, _translate("MainWindow", "xss-injection"))
        self.custom_scan_selector_comboBox.setItemText(3, _translate("MainWindow", "broken authentication"))
        self.custom_scan_selector_comboBox.setItemText(4, _translate("MainWindow", "csrf scan"))
        self.custom_scan_pushButton.setText(_translate("MainWindow", "Custom Scan"))
        self.generate_custom_scan_report_pushButton.setText(_translate("MainWindow", "Generate Detailed Report"))
        self.reset_scanner_pushButton.setText(_translate("MainWindow", "Reset Scanners"))
        self.num_of_custom_scan_label.setText(_translate("MainWindow", "Total No. of Custom Scans:"))
        self.custom_scan_history_label.setText(_translate("MainWindow", "History of custom scans:"))
        self.view_custom_scan_history_pushButton_2.setText(_translate("MainWindow", "View Custom Scan History"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.custom_scan_tab), _translate("MainWindow", "Custom Scan"))
        self.search_history_label.setText(_translate("MainWindow", "Search History"))
        self.search_history_lineEdit.setPlaceholderText(_translate("MainWindow", "enter url"))
        self.view_full_scan_history_pushButton.setText(_translate("MainWindow", "View Full Scan History"))
        self.view_custom_scan_history_pushButton.setText(_translate("MainWindow", "View Custom Scan History"))
        self.clear_history_comboBox.setCurrentText(_translate("MainWindow", "Delete Full Scan History"))
        self.clear_history_comboBox.setItemText(0, _translate("MainWindow", "Delete Full Scan History"))
        self.clear_history_comboBox.setItemText(1, _translate("MainWindow", "Delete Custom Scan History"))
        self.clear_history_comboBox.setItemText(2, _translate("MainWindow", "Delete everything"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.history_tab), _translate("MainWindow", "History"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.about_tab), _translate("MainWindow", "About"))
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
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.profile_tab), _translate("MainWindow", "Profile"))
