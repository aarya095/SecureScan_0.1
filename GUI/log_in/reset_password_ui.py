from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QMessageBox

class ResetPasswordWindow(QtWidgets.QMainWindow):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(431, 451)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setMinimumSize(QtCore.QSize(431, 451))
        MainWindow.setMaximumSize(QtCore.QSize(431, 451))
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.centralwidget.sizePolicy().hasHeightForWidth())
        self.centralwidget.setSizePolicy(sizePolicy)
        self.centralwidget.setObjectName("centralwidget")
        self.bg_image_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.bg_image_label.setGeometry(QtCore.QRect(0, 0, 431, 451))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.bg_image_label.sizePolicy().hasHeightForWidth())
        self.bg_image_label.setSizePolicy(sizePolicy)
        self.bg_image_label.setText("")
        self.bg_image_label.setPixmap(QtGui.QPixmap("../SecureScan_01/icons/login3.jpg"))
        self.bg_image_label.setObjectName("bg_image_label")
        self.reset_password_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.reset_password_label.setGeometry(QtCore.QRect(100, 20, 341, 71))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.reset_password_label.sizePolicy().hasHeightForWidth())
        self.reset_password_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(24)
        font.setBold(True)
        font.setWeight(75)
        self.reset_password_label.setFont(font)
        self.reset_password_label.setStyleSheet("QLabel{\n"
"    color:white;\n"
"    background-color: rgba(255, 255, 255, 0);\n"
"    font-weight:bold;\n"
"}")
        self.reset_password_label.setObjectName("reset_password_label")
        self.enter_password_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.enter_password_label.setGeometry(QtCore.QRect(100, 90, 301, 28))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.enter_password_label.sizePolicy().hasHeightForWidth())
        self.enter_password_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala Text")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.enter_password_label.setFont(font)
        self.enter_password_label.setStyleSheet("QLabel {\n"
"    color:white;\n"
"    font-weight:bold;\n"
"}")
        self.enter_password_label.setObjectName("enter_password_label")
        self.new_password_txtfield = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.new_password_txtfield.setGeometry(QtCore.QRect(40, 180, 361, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.new_password_txtfield.sizePolicy().hasHeightForWidth())
        self.new_password_txtfield.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala Text")
        font.setPointSize(14)
        self.new_password_txtfield.setFont(font)
        self.new_password_txtfield.setStyleSheet("QLineEdit {\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.5px;\n"
"    border-color: grey;\n"
"    padding-left: 20px; \n"
"    padding-right: 20px;\n"
"}")
        self.new_password_txtfield.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.new_password_txtfield.setObjectName("new_password_txtfield")
        self.confirm_password_txtfield = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.confirm_password_txtfield.setGeometry(QtCore.QRect(40, 240, 361, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.confirm_password_txtfield.sizePolicy().hasHeightForWidth())
        self.confirm_password_txtfield.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala Text")
        font.setPointSize(14)
        self.confirm_password_txtfield.setFont(font)
        self.confirm_password_txtfield.setStyleSheet("QLineEdit {\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.5px;\n"
"    border-color: grey;\n"
"    padding-left: 20px; \n"
"    padding-right: 20px;\n"
"}")
        self.confirm_password_txtfield.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.confirm_password_txtfield.setObjectName("confirm_password_txtfield")
        self.set_password_button = QtWidgets.QPushButton(parent=self.centralwidget)
        self.set_password_button.setGeometry(QtCore.QRect(40, 350, 361, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.set_password_button.sizePolicy().hasHeightForWidth())
        self.set_password_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala UI")
        font.setPointSize(15)
        font.setBold(True)
        font.setItalic(False)
        font.setWeight(75)
        self.set_password_button.setFont(font)
        self.set_password_button.setStyleSheet("QPushButton {\n"
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
"    transform: scale(0.95);  /* Slight shrink effect */\n"
"}")
        self.set_password_button.setObjectName("set_password_button")
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.reset_password_label.setText(_translate("MainWindow", "Reset Password"))
        self.enter_password_label.setText(_translate("MainWindow", "Please enter the new password"))
        self.new_password_txtfield.setPlaceholderText(_translate("MainWindow", "new password"))
        self.confirm_password_txtfield.setPlaceholderText(_translate("MainWindow", "confirm password"))
        self.set_password_button.setText(_translate("MainWindow", "Set Password"))

    def close_reset_password_ui(self):
        self.close()
    def show_message(self, title, message):
        """Displays a popup message."""
        msg_box = QMessageBox()
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.exec()

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = ResetPasswordWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())
