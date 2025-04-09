from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QMessageBox
from Database.db_connection import DatabaseConnection

class LoginWindow(QtWidgets.QMainWindow):
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.db = DatabaseConnection()
        self.controller = None

    def closeEvent(self, event):
        print("🛑 Login window is closing...")
        if self.controller:
            self.controller.cleanup()
        event.accept()
    
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


        self.main_frame = QtWidgets.QFrame(parent=self.centralwidget)
        self.main_frame.setMinimumSize(QtCore.QSize(1001, 621))
        self.main_frame.setLayoutDirection(QtCore.Qt.LayoutDirection.LeftToRight)
        self.main_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.main_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.main_frame.setObjectName("main_frame")

        self.central_layout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.central_layout.setContentsMargins(0, 0, 0, 0)  # Remove margins
        self.central_layout.setSpacing(0)  # Remove spacing
        self.central_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter) 
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
        self.welcome_label = QtWidgets.QLabel(parent=self.main_frame)
        self.welcome_label.setGeometry(QtCore.QRect(270, 60, 641, 131))
        self.welcome_label.setText("Welcome back!")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.welcome_label.sizePolicy().hasHeightForWidth())
        self.welcome_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(48)
        font.setBold(True)
        font.setWeight(75)
        self.welcome_label.setFont(font)
        self.welcome_label.setStyleSheet("QLabel{\n"
"    color:white;\n"
"    background-color: rgba(255, 255, 255, 0);\n"
"    font-weight:bold;\n"
"}")
        self.welcome_label.setObjectName("welcome_label")
        self.enter_cred_label = QtWidgets.QLabel(parent=self.main_frame)
        self.enter_cred_label.setGeometry(QtCore.QRect(390, 200, 275, 28))
        self.enter_cred_label.setText(("Please enter your credentials"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.enter_cred_label.sizePolicy().hasHeightForWidth())
        self.enter_cred_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala Text")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.enter_cred_label.setFont(font)
        self.enter_cred_label.setStyleSheet("QLabel {\n"
"    color:white;\n"
"    font-weight:bold;\n"
"}")
        self.enter_cred_label.setObjectName("enter_cred_label")
        self.username_txtfield = QtWidgets.QLineEdit(parent=self.main_frame)
        self.username_txtfield.setGeometry(QtCore.QRect(320, 250, 361, 41))
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
        self.password_txtfield = QtWidgets.QLineEdit(parent=self.main_frame)
        self.password_txtfield.setGeometry(QtCore.QRect(320, 310, 361, 41))
        self.password_txtfield.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
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
        self.password_txtfield.setObjectName("password_txtfield")
        self.forgot_pass_linkbutton = QtWidgets.QCommandLinkButton(parent=self.main_frame)
        self.forgot_pass_linkbutton.setGeometry(QtCore.QRect(520, 350, 161, 41))
        self.forgot_pass_linkbutton.setText(("forgot password?"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.forgot_pass_linkbutton.sizePolicy().hasHeightForWidth())
        self.forgot_pass_linkbutton.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("57")
        font.setPointSize(12)
        font.setBold(True)
        font.setItalic(False)
        font.setUnderline(True)
        font.setWeight(75)
        self.forgot_pass_linkbutton.setFont(font)
        self.forgot_pass_linkbutton.setStyleSheet("QCommandLinkButton {\n"
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
        self.forgot_pass_linkbutton.setDescription("")
        self.forgot_pass_linkbutton.setObjectName("forgot_pass_linkbutton")
        self.login_button = QtWidgets.QPushButton(parent=self.main_frame)
        self.login_button.setGeometry(QtCore.QRect(320, 400, 361, 41))
        self.login_button.setText(("LOG IN"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.login_button.sizePolicy().hasHeightForWidth())
        self.login_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Nirmala UI")
        font.setPointSize(15)
        font.setBold(True)
        font.setItalic(False)
        font.setWeight(75)
        self.login_button.setFont(font)
        self.login_button.setStyleSheet("QPushButton {\n"
"    background-color:rgb(35, 222, 104);\n"
"    color: white;\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.1px;\n"
"    font-weight: bold;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: #27ae60;  /* Darker green */\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"    background-color: #1e8449;\n"
"}")
        self.login_button.setObjectName("login_button")
        self.line = QtWidgets.QFrame(parent=self.main_frame)
        self.line.setGeometry(QtCore.QRect(290, 470, 421, 16))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.line.sizePolicy().hasHeightForWidth())
        self.line.setSizePolicy(sizePolicy)
        self.line.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line.setObjectName("line")
        self.new_usr_label = QtWidgets.QLabel(parent=self.main_frame)
        self.new_usr_label.setGeometry(QtCore.QRect(350, 490, 181, 41))
        self.new_usr_label.setText(("New to SecureScan?"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.new_usr_label.sizePolicy().hasHeightForWidth())
        self.new_usr_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.new_usr_label.setFont(font)
        self.new_usr_label.setStyleSheet("QLabel{\n"
"    color:white;\n"
"    font-size: 17px;\n"
"    font-weight:bold;\n"
"}")
        self.new_usr_label.setObjectName("new_usr_label")
        self.signup_commandLinkButton = QtWidgets.QCommandLinkButton(parent=self.main_frame)
        self.signup_commandLinkButton.setGeometry(QtCore.QRect(520, 490, 91, 48))
        self.signup_commandLinkButton.setText(("Sign Up"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.signup_commandLinkButton.sizePolicy().hasHeightForWidth())
        self.signup_commandLinkButton.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("57")
        font.setPointSize(12)
        font.setBold(True)
        font.setItalic(False)
        font.setUnderline(True)
        font.setWeight(75)
        self.signup_commandLinkButton.setFont(font)
        self.signup_commandLinkButton.setStyleSheet("QCommandLinkButton {\n"
"    color: white;\n"
"    qproperty-icon: none;\n"
"    font: Nirmala text;\n"
"    font-size: 17px;\n"
"    font-weight:bold;\n"
"    text-decoration: underline;\n"
"    background-color: rgba(255, 255, 255, 0);\n"
"}")
        self.signup_commandLinkButton.setObjectName("signup_commandLinkButton")
        self.centralwidget.setLayout(self.central_layout)
        QtCore.QMetaObject.connectSlotsByName(self)

    def show_message(self, title, message):
        msg_box = QMessageBox(self)  
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setIcon(QMessageBox.Icon.Critical if title == "Error" else QMessageBox.Icon.Information)
        msg_box.exec()

    def resizeEvent(self, event):
        event.accept()
        self.bg_label.setGeometry(0, 0, self.width(), self.height())
        self.bg_label.setPixmap(QtGui.QPixmap("../SecureScan_01/icons/blur_login3.png").scaled(
                self.width(), self.height(), QtCore.Qt.AspectRatioMode.KeepAspectRatioByExpanding
        ))