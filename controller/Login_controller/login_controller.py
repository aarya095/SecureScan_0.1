from GUI.log_in.login_gui import LoginWindow
from user_authentication.login.login_logic import LoginLogic
from PyQt6.QtCore import QThread
from Worker.Login_worker.login_worker import LoginWorker

class LoginController:
    def __init__(self, view: LoginWindow):
        self.view = view
        self.model = LoginLogic()

        # Connect button to the controller’s login handler
        self.view.login_button.clicked.connect(self.handle_login)
        self.view.forgot_pass_linkbutton.clicked.connect(self.view.open_forgot_password_window)

        self.view.destroyed.connect(self.cleanup)


    def handle_login(self):
        username = self.view.username_txtfield.text().strip()
        password = self.view.password_txtfield.text().strip()

        # Prevent double clicks / disable UI if needed
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
            self.view.open_home_window()
        else:
            print("❌ Login failed block reached")
            self.view.show_message("Error", message)

    def cleanup(self):
        if hasattr(self, "thread") and self.thread.isRunning():
            print("🧹 Cleaning up thread...")
            self.thread.quit()
            self.thread.wait()  

