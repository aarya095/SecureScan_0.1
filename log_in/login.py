import customtkinter as ctk
from tkinter import messagebox
import Database.db_connection as db 
import bcrypt

def open_login_window():
    root = ctk.CTk()
    root.title("Log In")
    root.geometry("400x300+550+250")
    ctk.set_appearance_mode("light") 
    ctk.set_default_color_theme("green")

    def open_forgot_password_window():
        from log_in.forgot_password import open_forgot_password_window
        open_forgot_password_window(root)  

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
                else:
                    messagebox.showerror("Login Failed", "Invalid username or password")
            else:
                messagebox.showerror("Login Failed", "Invalid username or password")
        else:
            messagebox.showerror("Database Error", "Could not connect to database")

    login_label = ctk.CTkLabel(root, text="Log In", font=("Tahoma", 30))
    login_label.place(x=150, y=20)
    
    username_label = ctk.CTkLabel(root, text="Username:", font=("Arial", 12))
    username_label.place(x=50, y=100)

    enter_username = ctk.CTkEntry(root, font=("Arial", 12), width=200)
    enter_username.place(x=150, y=100)

    password_label = ctk.CTkLabel(root, text="Password:", font=("Arial", 12))
    password_label.place(x=50, y=140)

    enter_password = ctk.CTkEntry(root, font=("Arial", 12), show="*", width=200)
    enter_password.place(x=150, y=140)

    login_button = ctk.CTkButton(root, text="Log In", font=("Tahoma", 14), command=verify_user_credentials)
    login_button.place(x=160, y=200)

    forgot_password_button = ctk.CTkButton(root, text="Forgot Password?", font=("Tahoma", 14), command=open_forgot_password_window)
    forgot_password_button.place(x=120, y=250)

    root.protocol("WM_DELETE_WINDOW", root.destroy)  

    root.mainloop()

if __name__ == "__main__":
    open_login_window()