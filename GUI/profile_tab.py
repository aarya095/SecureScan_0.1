from PyQt6 import QtCore, QtGui, QtWidgets

class ProfileTab(QtWidgets.QWidget):
    def __init__(self, parent=None, tab_widget=None):
        super().__init__(parent)
        self.tabWidget = tab_widget
        self.setupUi()

    def setupUi(self):
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout(self)

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

        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.profile_tab_left_frame)

        # Labels with text set at creation
        self.username_label = QtWidgets.QLabel("Username:", parent=self.profile_tab_left_frame)
        self.username_label.setObjectName("subTitle")
        self.verticalLayout_7.addWidget(self.username_label)

        self.email_label = QtWidgets.QLabel("Email:", parent=self.profile_tab_left_frame)
        self.email_label.setObjectName("subTitle")
        self.verticalLayout_7.addWidget(self.email_label)

        self.time_date_acc_created_label = QtWidgets.QLabel("Time and Date of last login:", parent=self.profile_tab_left_frame)
        self.time_date_acc_created_label.setObjectName("subTitle")
        self.verticalLayout_7.addWidget(self.time_date_acc_created_label)

        self.last_login_date_time_label = QtWidgets.QLabel("Account created at:", parent=self.profile_tab_left_frame)
        self.last_login_date_time_label.setObjectName("subTitle")
        self.verticalLayout_7.addWidget(self.last_login_date_time_label)

        # Buttons
        self.log_out_pushButton = QtWidgets.QPushButton("Log Out", parent=self.profile_tab_left_frame)
        self.log_out_pushButton.setSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        self.verticalLayout_7.addWidget(self.log_out_pushButton)

        self.delete_account_pushButton = QtWidgets.QPushButton("Delete Account", parent=self.profile_tab_left_frame)
        self.delete_account_pushButton.setSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        self.verticalLayout_7.addWidget(self.delete_account_pushButton)

        self.horizontalLayout_4.addWidget(self.profile_tab_left_frame)

        # Right Frame
        self.profile_tab_right_frame = QtWidgets.QFrame(parent=self)
        self.profile_tab_right_frame.setSizePolicy(
            QtWidgets.QSizePolicy(
                QtWidgets.QSizePolicy.Policy.Expanding,
                QtWidgets.QSizePolicy.Policy.Expanding,
            )
        )
        self.profile_tab_right_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.profile_tab_right_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)

        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.profile_tab_right_frame)

        # Right Panel Labels with text set at creation
        self.num_of_full_scan_label = QtWidgets.QLabel("No. of full scans:", parent=self.profile_tab_right_frame)
        self.num_of_full_scan_label.setObjectName("subTitle")
        self.verticalLayout_8.addWidget(self.num_of_full_scan_label)

        self.num_of_custom_scan_label_2 = QtWidgets.QLabel("No. of custom scans:", parent=self.profile_tab_right_frame)
        self.num_of_custom_scan_label_2.setObjectName("subTitle")
        self.verticalLayout_8.addWidget(self.num_of_custom_scan_label_2)

        self.num_of_total_scan_label = QtWidgets.QLabel("Total no. of vulnerabilities found:", parent=self.profile_tab_right_frame)
        self.num_of_total_scan_label.setObjectName("subTitle")
        self.verticalLayout_8.addWidget(self.num_of_total_scan_label)

        self.num_of_total_vulnerabilities_label = QtWidgets.QLabel("Pie chart for percentage of each vulnerability", parent=self.profile_tab_right_frame)
        self.num_of_total_vulnerabilities_label.setObjectName("subTitle")
        self.verticalLayout_8.addWidget(self.num_of_total_vulnerabilities_label)

        # Graphics View
        self.vulnerabilities_pie_chart_graphicsView = QtWidgets.QGraphicsView(parent=self.profile_tab_right_frame)
        self.verticalLayout_8.addWidget(self.vulnerabilities_pie_chart_graphicsView)

        # Terms and Conditions Button
        self.terms_and_conditions_commandLinkButton = QtWidgets.QCommandLinkButton("Terms and Conditions", parent=self.profile_tab_right_frame)
        self.verticalLayout_8.addWidget(self.terms_and_conditions_commandLinkButton)

        self.horizontalLayout_4.addWidget(self.profile_tab_right_frame)

        self.retranslateUi()

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
