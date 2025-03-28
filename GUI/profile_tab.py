from PyQt6 import QtCore, QtGui, QtWidgets
from user_interface import Ui_MainWindow

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
        Ui_MainWindow.MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(Ui_MainWindow.MainWindow)
        self.tabWidget.setCurrentIndex(4)
        self.custom_scan_selector_comboBox.setCurrentIndex(0)
        self.clear_history_comboBox.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(Ui_MainWindow.MainWindow)

    