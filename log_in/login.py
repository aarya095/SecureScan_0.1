import customtkinter as ctk
from tkinter import messagebox
import Database.db_connection as db 
import main.dashboard as dashboard
import main.start as start
from PIL import Image
import bcrypt

def open_login_window():
    root = ctk.CTk()
    root.title("Log In")
    root.geometry("700x500+550+200")
    ctk.set_appearance_mode("light") 
    ctk.set_default_color_theme("green")

    logo = ctk.CTkImage(light_image=Image.open("icons/login_welcome.png"), size=(353.5, 500))
    logo_label = ctk.CTkLabel(root, image=logo, text="")
    logo_label.place(x=0,y=0)

    def open_forgot_password_window():
        from log_in.forgot_password import open_forgot_password_window
        open_forgot_password_window(root)  

    def open_start_window():
        root.destroy()
        start.open_start_window()

    def verify_user_credentials():
        username = enter_username.get().strip()
        password = enter_password.get().strip()

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
                    root.destroy()
                    dashboard.open_dashboard()
                else:
                    messagebox.showerror("Login Failed", "Invalid username or password")
            else:
                messagebox.showerror("Login Failed", "Invalid username or password")
        else:
            messagebox.showerror("Database Error", "Could not connect to database")

    login_label = ctk.CTkLabel(root, text="Log In", font=("Tahoma", 50, "bold"))
    login_label.place(x=450, y=80)

    enter_credentials_label = ctk.CTkLabel(root, text="Please enter you credentials", 
                                           font=("Tahoma", 15, "bold"))
    enter_credentials_label.place(x=420, y=140)
    
    username_label = ctk.CTkLabel(root, text="Username:", font=("Arial", 20))
    username_label.place(x=370, y=200)

    enter_username = ctk.CTkEntry(root, font=("Arial", 20), width=200,
                                  corner_radius=10, border_width=2,
                                  border_color="black")
    enter_username.place(x=480, y=200)

    password_label = ctk.CTkLabel(root, text="Password:", font=("Arial", 20))
    password_label.place(x=370, y=240)

    enter_password = ctk.CTkEntry(root, font=("Arial", 20), show="*", width=200,
                                  corner_radius=10, border_width=2,
                                  border_color="black")
    enter_password.place(x=480, y=240)

    login_button = ctk.CTkButton(root, text="Log In", font=("Tahoma", 20, "bold"), 
                                 height=40, width=200, 
                                 command=verify_user_credentials)
    login_button.place(x=430, y=300)

    forgot_password_button = ctk.CTkButton(root, text="Forgot Password?", font=("Tahoma", 20,"bold"), 
                                           height=40, width=200, 
                                            command=open_forgot_password_window)
    forgot_password_button.place(x=430, y=350)

    back_button = ctk.CTkButton(root, text="Back",
                                    font=("Tahoma", 20, "bold"),
                                    width=150, height=40,
                                    command=open_start_window)
    back_button.place(x=450, y=440)

    root.protocol("WM_DELETE_WINDOW", root.destroy)  

    root.mainloop()

if __name__ == "__main__":
    open_login_window()