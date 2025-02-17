import os
import re
import bcrypt
import customtkinter as ctk
from tkinter import messagebox
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import Database.db_connection as db

def get_user_email(username):
    db.connect_to_database()
    email = db.fetch_user_email(username)
    db.close_connection()
    return email

def send_email(email, otp):
    sender_email = os.getenv('ATHARVA_GMAIL_ID')
    sender_password = os.getenv('ATHARVA_GMAIL_PASSWORD')

    subject = "Secure Scan - OTP for password reset"
    body = f"Your OTP for resetting your password is: {otp}"

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

def verify_otp(sent_otp, entered_otp):
    return sent_otp == entered_otp

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def reset_password(username, new_password):
    hashed_password = hash_password(new_password)
    db.connect_to_database()
    query = "UPDATE login SET password=%s WHERE username=%s"
    db.execute_query(query, (hashed_password, username))
    db.close_connection()

def open_forgot_password_window(master):
    forgot_password_window = ctk.CTkToplevel(master)
    forgot_password_window.title("Forgot Password")
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("green")
    forgot_password_window.geometry("400x300+500+250")

    forgot_password_window.lift()
    forgot_password_window.grab_set()

    reset_password_label = ctk.CTkLabel(forgot_password_window, 
                                        text="Enter Username to reset password",
                                        wraplength=300,
                                        font=("Tahoma", 30,"bold"))
    reset_password_label.pack(pady=10)

    enter_username = ctk.CTkEntry(forgot_password_window, font=("Arial", 20),
                                  width=250)
    enter_username.pack(pady=10)
    enter_username.insert(0, "Username")
    enter_username.bind("<FocusIn>", lambda event: clear_username(event, enter_username))

    send_otp_button = ctk.CTkButton(forgot_password_window, text="Send OTP", 
                                    font=("Tahoma", 20,"bold"), 
                                    command=lambda: send_otp(enter_username, forgot_password_window))
    send_otp_button.pack(pady=10)

def clear_username(event, entry):
    if entry.get() == "Username":
        entry.delete(0, ctk.END)

def send_otp(enter_username, forgot_password_window):
    username = enter_username.get().strip()
    if not username:
        messagebox.showwarning("Input Error", "Please enter a username")
        return

    email = get_user_email(username)
    if email:
        otp = generate_otp()
        if send_email(email, otp):
            forgot_password_window.grab_release()
            forgot_password_window.withdraw()
            open_verify_otp_window(forgot_password_window.master, otp, username)
        else:
            messagebox.showerror("OTP Error", "Error sending OTP. Please try again.")
    else:
        messagebox.showerror("OTP Error", "Username not found in database.")

def generate_otp():
    return str(random.randint(100000, 999999))

def open_verify_otp_window(master, sent_otp, username):
    verify_otp_window = ctk.CTkToplevel(master)
    verify_otp_window.title("Verify OTP")
    verify_otp_window.geometry("400x300+500+250")
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("green")

    enter_otp_label = ctk.CTkLabel(verify_otp_window, 
                                   text="Enter OTP to Reset Password", 
                                   font=("Tahoma", 30,"bold"),
                                   wraplength=300)
    enter_otp_label.pack(pady=10)

    entered_otp = ctk.CTkEntry(verify_otp_window, font=("Arial", 20),
                               width=250)
    entered_otp.pack(pady=10)

    validate_button = ctk.CTkButton(verify_otp_window, text="Verify OTP",
                                     font=("Tahoma", 20),
                                     command=lambda: validate_otp(sent_otp, entered_otp.get(), verify_otp_window, username))
    validate_button.pack(pady=20)

def validate_otp(sent_otp, entered_otp, verify_otp_window, username):
    if verify_otp(sent_otp, entered_otp):
        verify_otp_window.destroy()
        open_reset_password_window(verify_otp_window.master, username)
    else:
        messagebox.showerror("Invalid OTP", "The OTP entered is incorrect.")

def open_reset_password_window(master, username):
    reset_password_window = ctk.CTkToplevel(master)
    reset_password_window.title("Reset Password")
    reset_password_window.geometry("400x300+500+250")

    new_password_label = ctk.CTkLabel(reset_password_window, 
                                      text="Enter New Password", 
                                      font=("Tahoma", 20))
    new_password_label.pack(pady=10)

    new_password = ctk.CTkEntry(reset_password_window, 
                                font=("Arial", 20), show="*"
                                ,width=250)
    new_password.pack(pady=10)

    confirm_password = ctk.CTkEntry(reset_password_window, 
                                    font=("Arial", 20), show="*",
                                    width=250)
    confirm_password.pack(pady=10)

    reset_button = ctk.CTkButton(reset_password_window, text="Reset Password", 
                                 font=("Tahoma", 20,"bold")
                                 , command=lambda: reset_password_action(username, new_password.get(), confirm_password.get(), reset_password_window))
    reset_button.pack(pady=20)

def reset_password_action(username, new_password, confirm_password, reset_password_window):
    validation_error = validate_password(new_password)

    if validation_error:
        messagebox.showerror("Password Error", validation_error)
        return

    if new_password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match")
        return

    reset_password(username, new_password)
    messagebox.showinfo("Password Reset", "Your password has been reset successfully.")
    reset_password_window.destroy()

def validate_password(password):
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

def run_forgot_password_window():
    root = ctk.CTk()
    root.withdraw() 
    open_forgot_password_window(root)
    root.mainloop()

if __name__ == "__main__":
    run_forgot_password_window()
