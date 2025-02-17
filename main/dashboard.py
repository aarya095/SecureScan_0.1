import customtkinter as ctk
from PIL import Image
import tkinter as tk

def open_dashboard():
    splash.destroy()

    # Set theme
    ctk.set_appearance_mode("light")  # "light", "dark", or "system"
    ctk.set_default_color_theme("green")  # "blue", "green", "dark-blue"

    # Initialize main window
    root = ctk.CTk()
    root.title("Home")
    root.geometry("700x500+550+200")

    # Placeholder text handling for entry widget
    placeholder_text = "Enter URL here..."

    def on_entry_click(event):
        if url_entry.get() == placeholder_text:
            url_entry.delete(0, ctk.END)
            url_entry.configure(text_color="black")  # Set text color

    def on_focus_out(event):
        if not url_entry.get().strip():
            url_entry.insert(0, placeholder_text)
            url_entry.configure(text_color="gray")  # Set placeholder color

    # Title label
    title_label = ctk.CTkLabel(root, text="URL Analyzer", 
                            font=("Arial", 20, "bold"),
                            text_color="white",
                            fg_color="#16A085",  # Background color
                            corner_radius=10,  # Rounded corners
                            width=250, height=40)
    title_label.place(x=225, y=30)

    # Entry field with placeholder
    url_entry = ctk.CTkEntry(root, width=300, font=("Verdana", 15),
                            text_color="black",
                            fg_color="white",  # Entry background color
                            border_width=2,
                            border_color="black")
    url_entry.insert(0, placeholder_text)
    url_entry.bind("<FocusIn>", on_entry_click)
    url_entry.bind("<FocusOut>", on_focus_out)
    url_entry.place(x=150, y=100)

    # Analyze button
    def analyze_url():
        print(f"Analyzing: {url_entry.get()}")

    scan_button = ctk.CTkButton(root, text="Analyze",
                                font=("Arial", 15, "bold"),
                                fg_color="#16A085",  # Button color
                                text_color="white",
                                hover_color="#1ABC9C",  # Hover effect
                                width=150, height=40,
                                command=analyze_url)
    scan_button.place(x=275, y=160)

    # Run the application
    root.mainloop()


splash = ctk.CTk()
splash.geometry("672x378+540+270")
splash.title("Loading...")
splash.overrideredirect(True)

logo = ctk.CTkImage(light_image=Image.open("icons/SecureScan_dashboard_logo.png"), size=(672, 378))
logo_label = ctk.CTkLabel(splash, image=logo, text="")
logo_label.pack(expand=True)

splash.after(2500, open_dashboard)
splash.mainloop()