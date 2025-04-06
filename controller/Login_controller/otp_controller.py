
from user_authentication.login.forgot_password import ForgotPasswordLogic, OTPVerificationLogic
from GUI.log_in.otp_verification_ui import OTPVerificationWindow

class OTPController:
    def __init__(self, view:OTPVerificationWindow, username: str):
        self.view = view
        self.username = username
        self.forgot_password_logic = ForgotPasswordLogic()
        self.otp_verification_logic = OTPVerificationLogic()

        self.view.verify_otp_button.clicked.connect(self.verify_otp)

        self.send_and_store_otp()

    def send_and_store_otp(self):
        otp, error = self.forgot_password_logic.send_otp(self.username)

        if error:
            self.view.show_message("Error", error)
            return

        self.otp_verification_logic.store_otp(self.username, otp)
        self.view.show_message("Success", "OTP sent to your registered email.")

    def verify_otp(self):
        entered_otp = self.view.otp_txtfield.text().strip()

        if not entered_otp:
            self.view.show_message("Error", "Please enter the OTP.")
            return

        success, message = self.otp_verification_logic.verify_otp(self.username, entered_otp)

        if success:
            self.view.show_message("Success", message)
            self.open_reset_password_window()
        else:
            self.view.show_message("Error", message)

    def open_reset_password_window(self):
        from GUI.log_in.reset_password_ui import ResetPasswordWindow
        from controller.Login_controller.reset_password_controller import ResetPasswordController

        self.reset_password_view = ResetPasswordWindow()
        self.reset_password_controller = ResetPasswordController(self.reset_password_view, self.username)

        self.reset_password_view.show()
        self.view.close()

            
