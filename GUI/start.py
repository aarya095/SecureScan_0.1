import customtkinter as ctk
import tkinter as tk
from PIL import Image
import log_in.login as lg

def open_start_window():
    root = ctk.CTk()
    root.title("Welcome To SecureScan")
    root.geometry("700x500+550+200")
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("green")
    root.configure(fg_color="#27ae60") 

    logo = ctk.CTkImage(light_image=Image.open("icons/main.png"), size=(500, 500))
    logo_label = ctk.CTkLabel(root, image=logo, text="")
    logo_label.place(x=0,y=0)

    def open_login_window():
        root.destroy()
        lg.open_login_window()

    login_button = ctk.CTkButton(root,
                                    text="Login",
                                    width=100, 
                                    height=50,
                                    fg_color="#27ae60", 
                                    bg_color="#27ae60",
                                    font=("Arial", 20, "bold"),
                                    command=open_login_window)
    login_button.place(x=100,y=400)

    new_user_button = ctk.CTkButton(root,
                                    text="Sign Up",
                                    width=100, 
                                    height=50,
                                    fg_color="#27ae60", 
                                    bg_color="#27ae60",
                                    font=("Arial", 20, "bold"),
                                    )
    new_user_button.place(x=300,y=400)

    root.mainloop()

if __name__ == "__main__":
    open_start_window()