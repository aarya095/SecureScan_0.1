from GUI.log_in.login_gui import LoginWindow
from user_authentication.login.login_logic import LoginLogic
from PyQt6.QtCore import QThread
from Worker.Login_worker.login_worker import LoginWorker

class LoginController:
    def __init__(self, view: LoginWindow):
        self.view = view
        self.model = LoginLogic()

        self.view.login_button.clicked.connect(self.handle_login)
        self.view.forgot_pass_linkbutton.clicked.connect(self.open_forgot_password_window)

        self.view.destroyed.connect(self.cleanup)


    def handle_login(self):
        username = self.view.username_txtfield.text().strip()
        password = self.view.password_txtfield.text().strip()

        self.view.login_button.setEnabled(False)

        db = self.model.db
        if not db.connect():
            self.view.show_message("Error", "Database connection failed.")
            self.view.login_button.setEnabled(True)
            return

        # Thread and worker setup
        self.thread = QThread()
        self.worker = LoginWorker(username, password)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_login_result)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def on_login_result(self, success, message):
        self.view.login_button.setEnabled(True)
        if success:
            print("✅ Login success block reached")
            self.view.show_message("Success", message)
            self.open_home_window()
        else:
            print("❌ Login failed block reached")
            self.view.show_message("Error", message)

    def open_forgot_password_window(self):
        from GUI.log_in.forgot_password_ui import ForgotPasswordWindow
        from controller.Login_controller.forgot_password_controller import ForgotPasswordController

        self.forgot_password_view = ForgotPasswordWindow()
        self.forgot_password_controller = ForgotPasswordController(self.forgot_password_view)

        self.forgot_password_view.show()
        self.view.hide()

    def open_home_window(self):
        from GUI.main_window_ui.user_interface import Ui_MainWindow
        from PyQt6 import QtWidgets

        stylesheet = Ui_MainWindow.load_stylesheet("GUI/theme_switch/dark_style.qss")
        QtWidgets.QApplication.instance().setStyleSheet(stylesheet)
        
        self.main_window = Ui_MainWindow()
        self.main_window.show()

        self.view.close()

    def cleanup(self):
        if hasattr(self, "thread") and self.thread.isRunning():
            print("🧹 Cleaning up thread...")
            self.thread.quit()
            self.thread.wait()  

