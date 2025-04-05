from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QMessageBox

class OTPVerificationWindow(QtWidgets.QMainWindow):
    
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):

        self.setObjectName("MainWindow")
        self.resize(431, 451)
        self.setMinimumSize(QtCore.QSize(431, 451))
        self.setMaximumSize(QtCore.QSize(431, 451))
        self.centralwidget = QtWidgets.QWidget(parent=self)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(parent=self.centralwidget)
        self.label.setGeometry(QtCore.QRect(0, 0, 431, 451))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy)
        self.label.setMinimumSize(QtCore.QSize(431, 451))
        self.label.setMaximumSize(QtCore.QSize(431, 451))
        self.label.setText("")
        self.label.setPixmap(QtGui.QPixmap("../SecureScan_01/icons/login3.jpg"))
        self.label.setObjectName("label")
        self.otp_verification_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.otp_verification_label.setGeometry(QtCore.QRect(100, 30, 341, 71))
        self.otp_verification_label.setText(("OTP Verification"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.otp_verification_label.sizePolicy().hasHeightForWidth())
        self.otp_verification_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(24)
        font.setBold(True)
        font.setWeight(75)
        self.otp_verification_label.setFont(font)
        self.otp_verification_label.setStyleSheet("QLabel{\n"
"    color:white;\n"
"    background-color: rgba(255, 255, 255, 0);\n"
"    font-weight:bold;\n"
"}")
        self.otp_verification_label.setObjectName("otp_verification_label")
        self.otp_txtfield = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.otp_txtfield.setGeometry(QtCore.QRect(40, 230, 361, 41))
        self.otp_txtfield.setPlaceholderText(("otp"))
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
        self.verify_otp_button.setGeometry(QtCore.QRect(40, 290, 361, 41))
        self.verify_otp_button.setText(("Verify OTP"))
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
        self.enter_otp_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.enter_otp_label.setGeometry(QtCore.QRect(140, 100, 201, 28))
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
        self.setCentralWidget(self.centralwidget)

        QtCore.QMetaObject.connectSlotsByName(self)
    
    def show_message(self, title, message):
        msg_box = QMessageBox(self)  
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setIcon(QMessageBox.Icon.Critical if title == "Error" else QMessageBox.Icon.Information)
        msg_box.exec()

    def open_reset_password_window(self):
        from GUI.log_in.reset_password_ui import ResetPasswordWindow 
        self.close()
        self.reset_password_window = ResetPasswordWindow()  
        self.reset_password_window.show()

