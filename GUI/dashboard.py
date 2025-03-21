import customtkinter as ctk
from PIL import Image
import tkinter as tk
from tkinter import messagebox

def open_dashboard():

    def show_splash():
        splash = ctk.CTk()
        splash.geometry("672x378+540+270")
        splash.title("Loading...")
        splash.overrideredirect(True)

        logo = ctk.CTkImage(light_image=Image.open("icons/SecureScan_dashboard_logo.png"), 
                            size=(672, 378))
        logo_label = ctk.CTkLabel(splash, image=logo, text="")
        logo_label.pack(expand=True)

        splash.after(3000, lambda: [splash.destroy(), show_dashboard()])
        splash.mainloop()

    def show_dashboard():

        ctk.set_appearance_mode("light") 
        ctk.set_default_color_theme("green") 

        root = ctk.CTk()
        root.title("Home")
        root.geometry("700x500+550+200")

        url_txtfield = ctk.CTkEntry(root, font=("Arial", 20), , width=200,
                                  corner_radius=10, border_width=2,
                                  border_color="black")
        url_txtfield.place(x=480, y=240)   

        scan_button = ctk.CTkButton(root, text="Log In", font=("Tahoma", 20, "bold"), 
                                 height=40, width=200)
        scan_button.place(x=430, y=300)    

        root.mainloop()

    show_splash()

if __name__ == "__main__":
    open_dashboard()