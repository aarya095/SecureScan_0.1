from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QMessageBox
from Database.db_connection import DatabaseConnection
from GUI.sign_up.terms_dialog import TermsDialog

class SignUpWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setObjectName("MainWindow")
        self.resize(1001, 621)
        self.setMinimumSize(QtCore.QSize(1001, 621))
        font = QtGui.QFont()
        font.setFamily("Pristina")
        font.setPointSize(18)
        self.setFont(font)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("../SecureScan_01/icons/S_logo.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.setWindowIcon(icon)
        self.setStyleSheet("""
    QMainWindow {  
        background-repeat: no-repeat;
        background-position: center;
    }
""")
        self.setTabShape(QtWidgets.QTabWidget.TabShape.Rounded)
        self.setDockNestingEnabled(False)

        self.centralwidget = QtWidgets.QWidget(parent=self)
        self.setCentralWidget(self.centralwidget)

        self.bg_label = QtWidgets.QLabel(self.centralwidget)
        self.bg_label.setGeometry(0, 0, self.width(), self.height())  
        self.bg_label.setPixmap(QtGui.QPixmap("../SecureScan_01/icons/blur_login3.png").scaled(
            self.width(), self.height(), QtCore.Qt.AspectRatioMode.KeepAspectRatioByExpanding
        ))

        def resize_bg():
            self.bg_label.setGeometry(0, 0, self.width(), self.height())
            self.bg_label.setPixmap(QtGui.QPixmap("../SecureScan_01/icons/blur_login3.png").scaled(
                self.width(), self.height(), QtCore.Qt.AspectRatioMode.KeepAspectRatioByExpanding
            ))

        self.resizeEvent = lambda event: resize_bg()

        self.main_frame = QtWidgets.QFrame(parent=self.centralwidget)
        self.main_frame.setMinimumSize(QtCore.QSize(1001, 621))
        self.main_frame.setLayoutDirection(QtCore.Qt.LayoutDirection.LeftToRight)
        self.main_frame.setFrameShape(QtWidgets.QFrame.Shape.Box)
        self.main_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Plain)
        self.main_frame.setObjectName("main_frame")

        self.central_layout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.central_layout.setContentsMargins(0, 0, 0, 0)  # Remove margins
        self.central_layout.setSpacing(0)  # Remove spacing
        self.central_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter) 
        self.centralwidget.setLayout(self.central_layout)
        self.central_layout.addWidget(self.main_frame, alignment=QtCore.Qt.AlignmentFlag.AlignCenter)

        self.image_label = QtWidgets.QLabel(parent=self.main_frame)
        self.image_label.setGeometry(QtCore.QRect(0, 0, 1001, 621))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.image_label.sizePolicy().hasHeightForWidth())
        self.image_label.setSizePolicy(sizePolicy)
        self.image_label.setAutoFillBackground(True)
        self.image_label.setText("")
        self.image_label.setPixmap(QtGui.QPixmap("../SecureScan_01/icons/login3.jpg"))
        self.image_label.setScaledContents(True)
        self.image_label.setObjectName("image_label")
        self.get_started_label = QtWidgets.QLabel(parent=self.main_frame)
        self.get_started_label.setGeometry(QtCore.QRect(330, 10, 471, 131))
        self.get_started_label.setText(("Get Started"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.get_started_label.sizePolicy().hasHeightForWidth())
        self.get_started_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(48)
        font.setBold(True)
        font.setWeight(75)
        self.get_started_label.setFont(font)
        self.get_started_label.setStyleSheet("QLabel{\n"
"    color:white;\n"
"    background-color: rgba(255, 255, 255, 0);\n"
"    font-weight:bold;\n"
"}")
        self.get_started_label.setObjectName("get_started_label")
        self.catch_line_label = QtWidgets.QLabel(parent=self.main_frame)
        self.catch_line_label.setGeometry(QtCore.QRect(330, 120, 451, 28))
        self.catch_line_label.setText(("Smart Scans. Stronger Security. Sign Up Today!"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.catch_line_label.sizePolicy().hasHeightForWidth())
        self.catch_line_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala Text")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.catch_line_label.setFont(font)
        self.catch_line_label.setStyleSheet("QLabel {\n"
"    color:white;\n"
"    font-weight:bold;\n"
"}")
        self.catch_line_label.setObjectName("catch_line_label")
        self.email_txtfield = QtWidgets.QLineEdit(parent=self.main_frame)
        self.email_txtfield.setGeometry(QtCore.QRect(320, 260, 361, 41))
        self.email_txtfield.setPlaceholderText(("Email"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.email_txtfield.sizePolicy().hasHeightForWidth())
        self.email_txtfield.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala Text")
        font.setPointSize(14)
        self.email_txtfield.setFont(font)
        self.email_txtfield.setStyleSheet("QLineEdit {\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.5px;\n"
"    border-color: grey;\n"
"    padding-left: 20px; \n"
"    padding-right: 20px;\n"
"}")
        self.email_txtfield.setInputMask("")
        self.email_txtfield.setText("")
        self.email_txtfield.setMaxLength(32763)
        self.email_txtfield.setObjectName("email_txtfield")
        self.password_txtfield = QtWidgets.QLineEdit(parent=self.main_frame)
        self.password_txtfield.setGeometry(QtCore.QRect(320, 320, 361, 41))
        self.password_txtfield.setPlaceholderText(("Password"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.password_txtfield.sizePolicy().hasHeightForWidth())
        self.password_txtfield.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala Text")
        font.setPointSize(14)
        self.password_txtfield.setFont(font)
        self.password_txtfield.setStyleSheet("QLineEdit {\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.5px;\n"
"    border-color: grey;\n"
"    padding-left: 20px;        \n"
"    padding-right: 20px;\n"
"}")
        self.password_txtfield.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.password_txtfield.setObjectName("password_txtfield")

        self.next_button = QtWidgets.QPushButton(parent=self.main_frame)
        self.next_button.setGeometry(QtCore.QRect(320, 470, 361, 41))
        self.next_button.setText(("Sign Up"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.next_button.sizePolicy().hasHeightForWidth())
        self.next_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala UI")
        font.setPointSize(15)
        font.setBold(True)
        font.setItalic(False)
        font.setWeight(75)
        self.next_button.setFont(font)
        self.next_button.setStyleSheet("QPushButton {\n"
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
        self.next_button.setObjectName("next_button")

        self.line = QtWidgets.QFrame(parent=self.main_frame)
        self.line.setGeometry(QtCore.QRect(290, 520, 421, 16))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.line.sizePolicy().hasHeightForWidth())
        self.line.setSizePolicy(sizePolicy)
        self.line.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line.setObjectName("line")
        self.already_have_acc_label = QtWidgets.QLabel(parent=self.main_frame)
        self.already_have_acc_label.setGeometry(QtCore.QRect(350, 540, 221, 41))
        self.already_have_acc_label.setText(("Already have an account?"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.already_have_acc_label.sizePolicy().hasHeightForWidth())
        self.already_have_acc_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(1)
        font.setBold(True)
        font.setWeight(75)
        self.already_have_acc_label.setFont(font)
        self.already_have_acc_label.setStyleSheet("QLabel{\n"
"    color:white;\n"
"    font-size: 17px;\n"
"    font-weight:bold;\n"
"}")
        self.already_have_acc_label.setObjectName("already_have_acc_label")
        self.login_commandLinkButton = QtWidgets.QCommandLinkButton(parent=self.main_frame)
        self.login_commandLinkButton.setGeometry(QtCore.QRect(570, 540, 71, 31))
        self.login_commandLinkButton.setText(("Log In"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.login_commandLinkButton.sizePolicy().hasHeightForWidth())
        self.login_commandLinkButton.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("57")
        font.setPointSize(1)
        font.setBold(True)
        font.setItalic(False)
        font.setUnderline(True)
        font.setWeight(75)
        self.login_commandLinkButton.setFont(font)
        self.login_commandLinkButton.setStyleSheet("QCommandLinkButton {\n"
"    color: white;\n"
"    qproperty-icon: none;\n"
"    font: Nirmala text;\n"
"    font-size: 17px;\n"
"    font-weight:bold;\n"
"    text-decoration: underline;\n"
"    background-color: rgba(255, 255, 255, 0);\n"
"}\n"
"\n"
"QCommandLinkButton:pressed {\n"
"    background-color: lightgray;\n"
"    border: 2px solid gray;\n"
"    padding-left: 5px;  /* Slight move effect */\n"
"    padding-top: 3px;\n"
"}")
        self.login_commandLinkButton.setObjectName("login_commandLinkButton")
        self.username_txtfield = QtWidgets.QLineEdit(parent=self.main_frame)
        self.username_txtfield.setGeometry(QtCore.QRect(320, 200, 361, 41))
        self.username_txtfield.setPlaceholderText(("Username"))
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
        self.I_agree_checkBox = QtWidgets.QCheckBox(parent=self.main_frame)
        self.I_agree_checkBox.setGeometry(QtCore.QRect(340, 420, 131, 41))
        self.I_agree_checkBox.setText(("I agree with"))
        self.I_agree_checkBox.setStyleSheet("QCheckBox {\n"
"    color: white;\n"
"    qproperty-icon: none;\n"
"    font: Nirmala text;\n"
"    font-size: 17px;\n"
"    font-weight:bold;\n"
"    background-color: rgba(255, 255, 255, 0);\n"
"}")
        self.I_agree_checkBox.setObjectName("I_agree_checkBox")
        self.terms_conditions_commandLinkButton = QtWidgets.QCommandLinkButton(parent=self.main_frame)
        self.terms_conditions_commandLinkButton.setGeometry(QtCore.QRect(460, 420, 191, 31))
        self.terms_conditions_commandLinkButton.setText(("Terms and Conditions"))
        self.terms_conditions_commandLinkButton.setStyleSheet("QCommandLinkButton {\n"
"    color: white;\n"
"    qproperty-icon: none;\n"
"    font: Nirmala text;\n"
"    font-size: 17px;\n"
"    font-weight:bold;\n"
"    text-decoration: underline;\n"
"    background-color: rgba(255, 255, 255, 0);\n"
"}\n"
"\n"
"QCommandLinkButton:pressed {\n"
"    background-color: lightgray;\n"
"    border: 2px solid gray;\n"
"    padding-left: 5px;  /* Slight move effect */\n"
"    padding-top: 3px;\n"
"}")
        self.terms_conditions_commandLinkButton.setObjectName("terms_conditions_commandLinkButton")
        
        self.confirm_password_txtfield = QtWidgets.QLineEdit(parent=self.main_frame)
        self.confirm_password_txtfield.setGeometry(QtCore.QRect(320, 380, 361, 41))
        self.confirm_password_txtfield.setPlaceholderText(("Confirm Password"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
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
        self.setCentralWidget(self.centralwidget)

        QtCore.QMetaObject.connectSlotsByName(self)
    def show_terms_dialog(self):
        dialog = TermsDialog(self)
        dialog.exec()

    def show_message(self, title, message):
        msg_box = QMessageBox(self)  
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setIcon(QMessageBox.Icon.Critical if title == "Error" else QMessageBox.Icon.Information)
        msg_box.exec()

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = SignUpWindow()
    MainWindow.show()
    sys.exit(app.exec())