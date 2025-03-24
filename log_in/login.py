import customtkinter as ctk
from tkinter import messagebox
import Database.db_connection as db
import GUI.dashboard as dashboard
import GUI.start as start
from PIL import Image
import bcrypt


class LoginWindow:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Log In")
        self.root.geometry("700x500+550+200")
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("green")

        self.create_widgets()
        self.root.mainloop()

    def create_widgets(self):
        """Create all widgets in the login window."""
        logo = ctk.CTkImage(light_image=Image.open("icons/login_welcome.png"), size=(353.5, 500))
        logo_label = ctk.CTkLabel(self.root, image=logo, text="")
        logo_label.place(x=0, y=0)

        login_label = ctk.CTkLabel(self.root, text="Log In", font=("Tahoma", 50, "bold"))
        login_label.place(x=450, y=80)

        enter_credentials_label = ctk.CTkLabel(self.root, text="Please enter your credentials", font=("Tahoma", 15, "bold"))
        enter_credentials_label.place(x=420, y=140)

        username_label = ctk.CTkLabel(self.root, text="Username:", font=("Arial", 20))
        username_label.place(x=370, y=200)

        self.enter_username = ctk.CTkEntry(self.root, font=("Arial", 20), width=200, corner_radius=10, border_width=2, border_color="black")
        self.enter_username.place(x=480, y=200)

        password_label = ctk.CTkLabel(self.root, text="Password:", font=("Arial", 20))
        password_label.place(x=370, y=240)

        self.enter_password = ctk.CTkEntry(self.root, font=("Arial", 20), show="*", width=200, corner_radius=10, border_width=2, border_color="black")
        self.enter_password.place(x=480, y=240)

        login_button = ctk.CTkButton(self.root, text="Log In", font=("Tahoma", 20, "bold"), height=40, width=200, command=self.verify_user_credentials)
        login_button.place(x=430, y=300)

        forgot_password_button = ctk.CTkButton(self.root, text="Forgot Password?", font=("Tahoma", 20, "bold"), height=40, width=200, command=self.open_forgot_password_window)
        forgot_password_button.place(x=430, y=350)

        back_button = ctk.CTkButton(self.root, text="Back", font=("Tahoma", 20, "bold"), width=150, height=40, command=self.open_start_window)
        back_button.place(x=450, y=440)

        self.root.protocol("WM_DELETE_WINDOW", self.root.destroy)

    def verify_user_credentials(self):
        """Verify user credentials and proceed to dashboard if correct."""
        username = self.enter_username.get().strip()
        password = self.enter_password.get().strip()

        if not username or not password:
            messagebox.showwarning("Login Failed", "Please enter both username and password")
            return

        db.connect_to_database()
        if db.connection:
            query = "SELECT password FROM login WHERE username=%s"
            result = db.fetch_all(query, (username,))
            db.close_connection()

            if result:
                stored_hashed_password = result[0][0]
                if bcrypt.checkpw(password.encode(), stored_hashed_password.encode()):
                    messagebox.showinfo("Login Success", "Welcome to Secure Scan")
                    self.root.destroy()
                    dashboard.open_dashboard()
                else:
                    messagebox.showerror("Login Failed", "Invalid username or password")
            else:
                messagebox.showerror("Login Failed", "Invalid username or password")
        else:
            messagebox.showerror("Database Error", "Could not connect to database")

    def open_forgot_password_window(self):
        """Open forgot password window."""
        self.root.destroy()
        ForgotPasswordWindow()

    def open_start_window(self):
        """Go back to start window."""
        self.root.destroy()
        start.open_start_window()


if __name__ == "__main__":
    LoginWindow()
