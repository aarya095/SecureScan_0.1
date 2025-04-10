from PyQt6.QtCore import QThread
from Worker.Signup_workers.signup_worker import SignupWorker
from GUI.sign_up.signup_gui import SignUpWindow
import re

class SignupController:

    def __init__(self, view: SignUpWindow):
        self.view = view
        self.view.next_button.clicked.connect(self.handle_signup)
        self.view.terms_conditions_commandLinkButton.clicked.connect(self.view.show_terms_dialog)
        self.view.login_commandLinkButton.clicked.connect(self.open_log_in_window)

    def handle_signup(self):
        username = self.view.username_txtfield.text().strip()
        email = self.view.email_txtfield.text().strip()
        password = self.view.password_txtfield.text()
        confirm_password = self.view.confirm_password_txtfield.text()
        terms_accepted = self.view.I_agree_checkBox.isChecked()

        # Perform password validation first
        is_valid, message = self.is_strong_password(password)
        if not is_valid:
            self.view.show_message("Error", message)
            return

        # Continue with other checks
        if not username or not email or not password:
            self.view.show_message("Error", "Username, Email, and Password cannot be empty.")
            return

        if password != confirm_password:
            self.view.show_message("Error", "Passwords do not match.")
            return

        if not terms_accepted:
            self.view.show_message("Error", "You must accept the Terms & Conditions.")
            return

        # Now proceed with thread creation and database operation if all validations pass
        self.signup_worker = SignupWorker(username, email, password, confirm_password)
        self.signup_thread = QThread()
        self.signup_worker.moveToThread(self.signup_thread)

        # Connect the signals from the worker to the appropriate methods
        self.signup_worker.result_ready.connect(self.on_signup_result)
        self.signup_worker.error.connect(self.on_signup_error)

        # Ensure proper cleanup by connecting the thread's finished signal to the cleanup method
        self.signup_thread.finished.connect(self.on_signup_thread_finished)

        self.signup_thread.started.connect(self.signup_worker.run)
        self.signup_thread.start()

    def is_strong_password(self, password):
        """Checks whether the password meets the standard security rules."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"\d", password):
            return False, "Password must contain at least one digit."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character."
        return True, ""

    def on_signup_result(self, success):
        if success:
            self.view.show_message("Success", "🎉 Signup successful! You can now login.")
        else:
            self.view.show_message("Error", "⚠️ Signup failed.")

    def on_signup_error(self, message):
        print("Signup Error:", message)
        self.view.show_message("Error", f"Error during signup: {message}")

    def on_signup_thread_finished(self):
        # Properly clean up only after the thread has finished
        print("Thread finished. Cleaning up...")
        self.signup_worker.deleteLater()
        self.signup_thread.deleteLater()  # Ensure the thread is deleted after finishing

    def open_log_in_window(self):
        from GUI.log_in.login_gui import LoginWindow
        from controller.Login_controller.login_controller import LoginController
        
        self.log_in_window = LoginWindow()
        self.log_in_window_controller = LoginController(self.log_in_window)

        self.log_in_window.show()
        self.view.hide()


