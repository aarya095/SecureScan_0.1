from GUI.log_in.reset_password_ui import ResetPasswordWindow
from user_authentication.login.forgot_password import ResetPasswordLogic
from PyQt6.QtCore import QThread
from Worker.Login_worker.reset_password_worker import ResetPasswordWorker

class ResetPasswordController:
    def __init__(self, view: ResetPasswordWindow, username: str):
        self.view = view
        self.username = username
        self.model = ResetPasswordLogic(self.username)

        self.view.set_password_button.clicked.connect(self.on_reset_password_clicked)
        
        self.view.destroyed.connect(self.cleanup)

    def on_reset_password_clicked(self):
        new_password = self.view.new_password_txtfield.text().strip()
        confirm_password = self.view.confirm_password_txtfield.text().strip()

        self.view.set_password_button.setEnabled(False)

        self.thread = QThread()
        self.worker = ResetPasswordWorker(self.username, new_password, confirm_password)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.success.connect(self.on_password_reset_success)
        self.worker.error.connect(self.on_password_reset_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def on_password_reset_success(self, message):
        self.view.show_message("Success", message)
        self.open_login_window()

    def on_password_reset_error(self, message):
        self.view.show_message("Error", message)

    def open_login_window(self):
        from GUI.log_in.login_gui import LoginWindow
        from controller.Login_controller.login_controller import LoginController

        self.login_view = LoginWindow()
        self.login_controller = LoginController(self.login_view)

        self.login_view.show()
        self.view.close()

    def cleanup(self):
        if hasattr(self, "thread") and self.thread.isRunning():
            print("🧹 Cleaning up thread...")
            self.thread.quit()
            self.thread.wait()
