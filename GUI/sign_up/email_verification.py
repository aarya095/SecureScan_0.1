from PyQt6 import QtCore, QtGui, QtWidgets


class EmailVerificationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setObjectName("MainWindow")
        self.resize(431, 451)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(43)
        sizePolicy.setVerticalStretch(45)
        sizePolicy.setHeightForWidth(self.sizePolicy().hasHeightForWidth())
        self.setSizePolicy(sizePolicy)
        self.setMinimumSize(QtCore.QSize(431, 451))
        self.setMaximumSize(QtCore.QSize(431, 451))
        
        self.centralwidget = QtWidgets.QWidget(parent=self)
        self.centralwidget.setObjectName("centralwidget")
        
        self.bg_image_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.bg_image_label.setGeometry(QtCore.QRect(0, 0, 431, 451))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.bg_image_label.sizePolicy().hasHeightForWidth())
        self.bg_image_label.setSizePolicy(sizePolicy)
        self.bg_image_label.setMinimumSize(QtCore.QSize(431, 451))
        self.bg_image_label.setMaximumSize(QtCore.QSize(431, 451))
        self.bg_image_label.setText("")
        self.bg_image_label.setPixmap(QtGui.QPixmap("../SecureScan_01/icons/login3.jpg"))
        self.bg_image_label.setObjectName("bg_image_label")
        
        self.email_verification_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.email_verification_label.setGeometry(QtCore.QRect(40, 30, 361, 71))
        self.email_verification_label.setText(("Email Verification"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.email_verification_label.sizePolicy().hasHeightForWidth())
        self.email_verification_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(24)
        font.setBold(True)
        font.setWeight(75)
        self.email_verification_label.setFont(font)
        self.email_verification_label.setStyleSheet("QLabel{\n"
"    color:white;\n"
"    background-color: rgba(255, 255, 255, 0);\n"
"    font-weight:bold;\n"
"}")
        self.email_verification_label.setObjectName("email_verification_label")
        self.enter_otp_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.enter_otp_label.setGeometry(QtCore.QRect(110, 110, 201, 28))
        self.enter_otp_label.setText(("Please enter the otp"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.enter_otp_label.sizePolicy().hasHeightForWidth())
        self.enter_otp_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala Text")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.enter_otp_label.setFont(font)
        self.enter_otp_label.setStyleSheet("QLabel {\n"
"    color:white;\n"
"    font-weight:bold;\n"
"}")
        self.enter_otp_label.setObjectName("enter_otp_label")
        self.otp_txtfield = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.otp_txtfield.setGeometry(QtCore.QRect(40, 210, 361, 41))
        self.otp_txtfield.setPlaceholderText(("enter otp"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.otp_txtfield.sizePolicy().hasHeightForWidth())
        self.otp_txtfield.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala Text")
        font.setPointSize(14)
        self.otp_txtfield.setFont(font)
        self.otp_txtfield.setStyleSheet("QLineEdit {\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.5px;\n"
"    border-color: grey;\n"
"    padding-left: 20px; \n"
"    padding-right: 20px;\n"
"}")
        self.otp_txtfield.setObjectName("otp_txtfield")
        self.verify_otp_button = QtWidgets.QPushButton(parent=self.centralwidget)
        self.verify_otp_button.setGeometry(QtCore.QRect(40, 270, 361, 41))
        self.verify_otp_button.setText(("Verify Email"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.verify_otp_button.sizePolicy().hasHeightForWidth())
        self.verify_otp_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala UI")
        font.setPointSize(15)
        font.setBold(True)
        font.setItalic(False)
        font.setWeight(75)
        self.verify_otp_button.setFont(font)
        self.verify_otp_button.setStyleSheet("QPushButton {\n"
"    background-color:rgb(35, 222, 104);\n"
"    color: white;\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.1px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: #27ae60;  /* Darker green */\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"    background-color: #1e8449;\n"
"}")
        self.verify_otp_button.setObjectName("verify_otp_button")
        self.setCentralWidget(self.centralwidget)

        QtCore.QMetaObject.connectSlotsByName(self)

