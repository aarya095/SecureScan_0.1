from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QMessageBox

class ForgotPasswordWindow(QtWidgets.QMainWindow):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(431, 451)
        MainWindow.setMinimumSize(QtCore.QSize(431, 451))
        MainWindow.setMaximumSize(QtCore.QSize(431, 451))
        MainWindow.setStyleSheet("QMainWindow{\n"
"    background-color=white;\n"
"}")
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.bg_image_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.bg_image_label.setGeometry(QtCore.QRect(0, 0, 431, 451))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.bg_image_label.sizePolicy().hasHeightForWidth())
        self.bg_image_label.setSizePolicy(sizePolicy)
        self.bg_image_label.setMaximumSize(QtCore.QSize(431, 451))
        self.bg_image_label.setText("")
        self.bg_image_label.setPixmap(QtGui.QPixmap("../SecureScan_01/icons/login3.jpg"))
        self.bg_image_label.setObjectName("bg_image_label")
        self.forgot_password_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.forgot_password_label.setGeometry(QtCore.QRect(100, 40, 341, 71))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.forgot_password_label.sizePolicy().hasHeightForWidth())
        self.forgot_password_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(24)
        font.setBold(True)
        font.setWeight(75)
        self.forgot_password_label.setFont(font)
        self.forgot_password_label.setStyleSheet("QLabel{\n"
"    color:white;\n"
"    background-color: rgba(255, 255, 255, 0);\n"
"    font-weight:bold;\n"
"}")
        self.forgot_password_label.setObjectName("forgot_password_label")
        self.enter_username_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.enter_username_label.setGeometry(QtCore.QRect(130, 110, 231, 28))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.enter_username_label.sizePolicy().hasHeightForWidth())
        self.enter_username_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala Text")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.enter_username_label.setFont(font)
        self.enter_username_label.setStyleSheet("QLabel {\n"
"    color:white;\n"
"    font-weight:bold;\n"
"}")
        self.enter_username_label.setObjectName("enter_username_label")
        self.username_txtfield = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.username_txtfield.setGeometry(QtCore.QRect(40, 230, 361, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.username_txtfield.sizePolicy().hasHeightForWidth())
        self.username_txtfield.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala Text")
        font.setPointSize(14)
        self.username_txtfield.setFont(font)
        self.username_txtfield.setStyleSheet("QLineEdit {\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.5px;\n"
"    border-color: grey;\n"
"    padding-left: 20px; \n"
"    padding-right: 20px;\n"
"}")
        self.username_txtfield.setObjectName("username_txtfield")
        self.sent_otp_button = QtWidgets.QPushButton(parent=self.centralwidget)
        self.sent_otp_button.setGeometry(QtCore.QRect(40, 290, 361, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.sent_otp_button.sizePolicy().hasHeightForWidth())
        self.sent_otp_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala UI")
        font.setPointSize(15)
        font.setBold(True)
        font.setItalic(False)
        font.setWeight(75)
        self.sent_otp_button.setFont(font)
        self.sent_otp_button.setStyleSheet("QPushButton {\n"
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
        self.sent_otp_button.setObjectName("sent_otp_button")
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.forgot_password_label.setText(_translate("MainWindow", "Forgot Password"))
        self.enter_username_label.setText(_translate("MainWindow", "Please enter your username"))
        self.username_txtfield.setPlaceholderText(_translate("MainWindow", "username"))
        self.sent_otp_button.setText(_translate("MainWindow", "Send OTP"))

    def show_message(self, title, message):
        """Displays a popup message."""
        msg_box = QMessageBox()
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.exec()
    
    def open_otp_verification_window(self):
        
        from GUI.log_in.otp_verification_ui import OTPVerificationWindow 
        self.close()
        self.otp_verification_window = OTPVerificationWindow()  
        self.otp_verification_window.show()

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = ForgotPasswordWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())
