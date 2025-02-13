import os
import re
import sys
import bcrypt
import tkinter as tk
from tkinter import messagebox
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from Database.db_connection import DatabaseConnection
from log_in.login import LoginWindow

class UserVerification:
    def __init__(self, username):
        self.username = username
        self.db = DatabaseConnection()
        self.db.connect_to_database()

    def get_user_email(self):
        email = self.db.fetch_user_email(self.username)
        self.db.close_connection()
        return email

class OTPSender:
    def __init__(self, email, otp):
        self.email = email
        self.otp = otp
        self.sender_email = os.getenv('ATHARVA_GMAIL_ID')
        self.sender_password = os.getenv('ATHARVA_GMAIL_PASSWORD')

    def send_email(self):
        subject = "Secure Scan - OTP for password reset"
        body = f"Your OTP for resetting your password is: {self.otp}"

        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = self.email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, self.email, msg.as_string())
                print("OTP sent successfully.")
                return True
        except smtplib.SMTPAuthenticationError:
            print("SMTP Authentication Error: Please check your email address and password.")
            return False
        except smtplib.SMTPException as e:
            print(f"SMTP Error: {e}")
            return False
        except Exception as e:
            print(f"An error occurred while sending OTP: {e}")
            return False

class OTPVerifier:
    def __init__(self, sent_otp):
        self.sent_otp = sent_otp

    def verify(self, entered_otp):
        return self.sent_otp == entered_otp

class PasswordReset:
    def __init__(self, username, new_password):
        self.username = username
        self.new_password = new_password
        self.db = DatabaseConnection()
        self.db.connect_to_database()

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password

    def reset_password(self):
        hashed_password = self.hash_password(self.new_password)
        query = "UPDATE login SET password=%s WHERE username=%s"
        self.db.execute_query(query, (hashed_password, self.username))
        self.db.close_connection()

class ForgotPasswordWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Forgot Password")
        self.geometry("400x300+500+250")

        tk.Label(self, text="Enter Username to reset password", font=("Tahoma", 14)).pack(pady=10)

        self.enter_username = tk.Entry(self, font=("Arial", 12))
        self.enter_username.pack(pady=5)
        self.enter_username.insert(0, "Username")
        self.enter_username.bind("<FocusIn>", self.clear_username)

        self.send_otp_button = tk.Button(self, text="Send OTP", font=("Tahoma", 12), command=self.send_otp)
        self.send_otp_button.pack(pady=10)

    def clear_username(self, event):
        if self.enter_username.get() == "Username":
            self.enter_username.delete(0, tk.END)

    def send_otp(self):
        username = self.enter_username.get().strip()

        if not username:
            messagebox.showwarning("Input Error", "Please enter a username")
            return

        user_verifier = UserVerification(username)
        email = user_verifier.get_user_email()

        if email:
            otp = self.generate_otp()
            otp_sender = OTPSender(email, otp)
            if otp_sender.send_email():
                self.withdraw()
                VerifyOTPWindow(self.master, self, otp, username)
            else:
                messagebox.showerror("OTP Error", "Error sending OTP. Please try again.")
        else:
            messagebox.showerror("OTP Error", "Username not found in database.")

    def generate_otp(self):
        return str(random.randint(100000, 999999))

class VerifyOTPWindow(tk.Toplevel):
    def __init__(self, master, forgot_password_window, sent_otp, username):
        super().__init__(master)
        self.forgot_password_window = forgot_password_window
        self.sent_otp = sent_otp
        self.username = username
        self.title("Verify OTP")
        self.geometry("300x200+500+250")

        tk.Label(self, text="Enter OTP to Reset Password", font=("Tahoma", 12)).pack(pady=10)

        self.entered_otp = tk.Entry(self, font=("Arial", 12))
        self.entered_otp.pack(pady=5)

        validate_button = tk.Button(self, text="Verify OTP", font=("Tahoma", 12), command=self.validate_otp)
        validate_button.pack(pady=20)

        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def validate_otp(self):
        otp_verifier = OTPVerifier(self.sent_otp)
        if otp_verifier.verify(self.entered_otp.get().strip()):
            self.destroy()
            ResetPasswordWindow(self.master, self.username, self.forgot_password_window)
        else:
            messagebox.showerror("Invalid OTP", "The OTP entered is incorrect.")

class ResetPasswordWindow(tk.Toplevel):
    def __init__(self, master, username, forgot_password_window):
        super().__init__(master)
        self.username = username
        self.forgot_password_window = forgot_password_window
        self.title("Reset Password")
        self.geometry("400x300+500+250")

        tk.Label(self, text="Enter New Password", font=("Tahoma", 14)).pack(pady=10)

        self.new_password = tk.Entry(self, font=("Arial", 12), show="*")
        self.new_password.pack(pady=5)

        self.confirm_password = tk.Entry(self, font=("Arial", 12), show="*")
        self.confirm_password.pack(pady=5)

        reset_button = tk.Button(self, text="Reset Password", font=("Tahoma", 12), bg="black", fg="white",
                                 command=self.reset_password)
        reset_button.pack(pady=20)

    def validate_password(self, password):
        if len(password) < 8:
            return "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]",password):
            return "Password must contain at least one lowercase letter."
        if not re.search(r"\d", password):
            return "Password must contain at least one digit."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return "Password must contain at least one special character (!@#$%^&* etc.)."
        return None

    def fetch_old_password(self):

        db = DatabaseConnection()
        db.connect_to_database()

        query = "select password from login where username = %s"
        result = db.fetch_all(query, (self.username,))

        db.close_connection()

        if result:
            return result[0][0]
        return None

    def reset_password(self):
        new_password = self.confirm_password.get()
        confirm_password = self.confirm_password.get()

        validation_error = self.validate_password(new_password)

        if validation_error:
            messagebox.showerror("Password Error", validation_error)
            return

        old_hashed_password = self.fetch_old_password()
        if old_hashed_password and bcrypt.checkpw(new_password.encode(), old_hashed_password.encode()):
            messagebox.showinfo("Password Error","New password cannot be as the same as old password.")
            return

        if self.new_password.get() == self.confirm_password.get():
            password_reset = PasswordReset(self.username, self.new_password.get())
            password_reset.reset_password()
            messagebox.showinfo("Password Reset", "Your password has been reset successfully.")
            self.destroy()
            self.forgot_password_window.destroy()
            self.open_login_window()
        else:
            messagebox.showerror("Error", "Passwords do not match")

    def open_login_window(self):
        login_window = LoginWindow(self.master)
        login_window.deiconify()

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    forgot_password_window = ForgotPasswordWindow(root)
    forgot_password_window.mainloop()
