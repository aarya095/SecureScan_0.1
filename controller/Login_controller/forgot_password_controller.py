from GUI.log_in.forgot_password_ui import ForgotPasswordWindow
from user_authentication.login.forgot_password import ForgotPasswordLogic
from PyQt6.QtCore import QThread
from Worker.Login_worker.forgot_password_worker import ForgotPasswordWorker

class ForgotPasswordController:
    def __init__(self, view: ForgotPasswordWindow):
        self.view = view
        self.model = ForgotPasswordLogic()

        self.view.sent_otp_button.clicked.connect(self.on_send_otp_clicked)
        
        self.view.destroyed.connect(self.cleanup)

    def on_send_otp_clicked(self):
        username = self.view.username_txtfield.text().strip()

        self.view.sent_otp_button.setEnabled(False)
        
        self.thread = QThread()
        self.logic = ForgotPasswordLogic()
        self.worker = ForgotPasswordWorker(username, self.logic)
        
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)

        self.worker.success.connect(self.handle_otp_success)
        self.worker.error.connect(self.handle_otp_error)

        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def handle_otp_success(self, otp):
        self.view.show_message("OTP Sent", f"OTP sent successfully: {otp}")
        self.open_otp_verification_window()

    def handle_otp_error(self, error_message):
        self.view.show_message("Error", error_message)

    def open_otp_verification_window(self):
        from GUI.log_in.otp_verification_ui import OTPVerificationWindow
        from controller.Login_controller.otp_controller import OTPController

        username = self.view.username_txtfield.text().strip()

        self.otp_verification_view = OTPVerificationWindow()
        self.otp_verification_controller = OTPController(self.otp_verification_view, username)
        self.otp_verification_view.show()
        self.view.close()

    def cleanup(self):
        if hasattr(self, "thread") and self.thread.isRunning():
            print("🧹 Cleaning up thread...")
            self.thread.quit()
            self.thread.wait()