import customtkinter as ctk
from tkinter import messagebox
import random
import bcrypt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import Database.db_connection as db

class ResetPasswordWindow:
    def __init__(self, username):
        self.username = username

        self.root = ctk.CTk()
        self.root.title("Reset Password")
        self.root.geometry("400x300+500+250")

        self.create_widgets()
        self.root.mainloop()

    def create_widgets(self):
        label = ctk.CTkLabel(self.root, text="Enter New Password", font=("Tahoma", 18, "bold"))
        label.pack(pady=10)

        self.new_password_entry = ctk.CTkEntry(self.root, font=("Arial", 15), width=250, show="*")
        self.new_password_entry.pack(pady=5)

        label_confirm = ctk.CTkLabel(self.root, text="Confirm Password", font=("Tahoma", 18, "bold"))
        label_confirm.pack(pady=5)

        self.confirm_password_entry = ctk.CTkEntry(self.root, font=("Arial", 15), width=250, show="*")
        self.confirm_password_entry.pack(pady=5)

        reset_button = ctk.CTkButton(self.root, text="Reset Password", font=("Tahoma", 15), command=self.reset_password)
        reset_button.pack(pady=10)

    def reset_password(self):
        new_password = self.new_password_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()

        if not new_password or not confirm_password:
            messagebox.showerror("Error", "Please enter all fields")
            return

        validation_error = self.validate_password(new_password)
        if validation_error:
            messagebox.showerror("Password Error", validation_error)
            return

        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        hashed_password = self.hash_password(new_password)
        self.update_password_in_database(hashed_password)

        messagebox.showinfo("Success", "Password reset successfully. You can now log in with your new password.")
        self.root.destroy()

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

class VerifyOTPWindow:
    def __init__(self, username, otp):
        self.username = username
        self.otp = otp

        self.root = ctk.CTk()
        self.root.title("Verify OTP")
        self.root.geometry("400x300+500+250")

        self.create_widgets()
        self.root.mainloop()

    def create_widgets(self):
        label = ctk.CTkLabel(self.root, text="Enter OTP to Reset Password", font=("Tahoma", 18, "bold"))
        label.pack(pady=10)

        self.otp_entry = ctk.CTkEntry(self.root, font=("Arial", 15), width=250)
        self.otp_entry.pack(pady=10)

        verify_button = ctk.CTkButton(self.root, text="Verify OTP", font=("Tahoma", 15), command=self.verify_otp)
        verify_button.pack(pady=10)

    def verify_otp(self):
        entered_otp = self.otp_entry.get().strip()
        if entered_otp == self.otp:
            messagebox.showinfo("Success", "OTP Verified. Proceed to reset password.")
            self.root.destroy()
            ResetPasswordWindow(self.username)  # Open the password reset window
        else:
            messagebox.showerror("Error", "Invalid OTP. Please try again.")


class ForgotPasswordWindow:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Forgot Password")
        self.root.geometry("400x300+500+250")
        self.root.lift()
        self.root.grab_set()
        self.create_widgets()
        self.root.mainloop()

    def create_widgets(self):
        """Create widgets for forgot password window."""
        label = ctk.CTkLabel(self.root, text="Enter Username to Reset Password", font=("Tahoma", 18, "bold"))
        label.pack(pady=10)

        self.username_entry = ctk.CTkEntry(self.root, font=("Arial", 15), width=250)
        self.username_entry.pack(pady=10)

        send_otp_button = ctk.CTkButton(self.root, text="Send OTP", font=("Tahoma", 15), command=self.send_otp)
        send_otp_button.pack(pady=10)

    def send_otp(self):
        """Send OTP to user email."""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Input Error", "Please enter a username")
            return

        email = self.get_user_email(username)
        if email:
            self.otp = self.generate_otp()
            if self.send_email(email, self.otp):
                messagebox.showinfo("OTP Sent", "Check your email for the OTP.")
                self.root.destroy()
                VerifyOTPWindow(username, self.otp)
            else:
                messagebox.showerror("OTP Error", "Failed to send OTP.")
        else:
            messagebox.showerror("Error", "Username not found.")

    def get_user_email(self, username):
        """Retrieve user email from database."""
        db.connect_to_database()
        email = db.fetch_user_email(username)
        db.close_connection()
        return email

    def send_email(self, email, otp):
        """Send OTP via email."""
        sender_email = "your_email@gmail.com"
        sender_password = "your_password"
        subject = "Secure Scan - OTP for password reset"
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

    def generate_otp(self):
        """Generate a 6-digit OTP."""
        return str(random.randint(100000, 999999))


if __name__ == "__main__":
    ForgotPasswordWindow()
