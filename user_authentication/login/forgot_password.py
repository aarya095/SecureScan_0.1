import random
import bcrypt
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import Database.db_connection as db


class ForgotPasswordLogic:
    def __init__(self):
        pass

    def send_otp(self, username):
        """Retrieve user email and send OTP."""
        email = self.get_user_email(username)
        if not email:
            return None, "Username not found."

        otp = self.generate_otp()
        success = self.send_email(email, otp)

        if success:
            return otp, None  # OTP sent successfully
        else:
            return None, "Failed to send OTP."

    def get_user_email(self, username):
        """Retrieve user email from the database."""
        db.connect_to_database()
        email = db.fetch_user_email(username)
        db.close_connection()
        return email

    def generate_otp(self):
        """Generate a 6-digit OTP."""
        return str(random.randint(100000, 999999))

    def send_email(self, email, otp):
        """Send OTP via email."""
        sender_email = "your_email@gmail.com"
        sender_password = "your_password"
        subject = "Secure Scan - OTP for Password Reset"
        body = f"Your OTP is: {otp}"

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, email, msg.as_string())
                return True
        except Exception as e:
            print(f"Email error: {e}")
            return False


class ResetPasswordLogic:
    def __init__(self, username):
        self.username = username

    def reset_password(self, new_password, confirm_password):
        """Validate and update password in the database."""
        if not new_password or not confirm_password:
            return "Please enter all fields."

        validation_error = self.validate_password(new_password)
        if validation_error:
            return validation_error

        if new_password != confirm_password:
            return "Passwords do not match."

        hashed_password = self.hash_password(new_password)
        self.update_password_in_database(hashed_password)

        return "Password reset successfully."

    def validate_password(self, password):
        """Checks if the password meets security requirements."""
        if len(password) < 8:
            return "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return "Password must contain at least one lowercase letter."
        if not re.search(r"\d", password):
            return "Password must contain at least one digit."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return "Password must contain at least one special character (!@#$%^&* etc.)."
        return None

    def hash_password(self, password):
        """Hashes the password using bcrypt."""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def update_password_in_database(self, hashed_password):
        """Updates the user's password in the database."""
        db.connect_to_database()
        query = "UPDATE login SET password=%s WHERE username=%s"
        db.execute_query(query, (hashed_password, self.username))
        db.close_connection()
