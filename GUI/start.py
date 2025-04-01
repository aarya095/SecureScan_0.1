import customtkinter as ctk
from PIL import Image

class SecureScanApp:
    """Class-based GUI application for SecureScan's start window."""

    def __init__(self):
        """Initialize the main window."""
        self.root = ctk.CTk()
        self.root.title("Welcome To SecureScan")
        self.root.geometry("700x500+550+200")
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("green")
        self.root.configure(fg_color="#27ae60") 

        self.create_widgets()

    def create_widgets(self):
        """Create and place UI components."""
        # Logo
        logo = ctk.CTkImage(light_image=Image.open("icons/main.png"), size=(500, 500))
        logo_label = ctk.CTkLabel(self.root, image=logo, text="")
        logo_label.place(x=0, y=0)

        # Buttons
        login_button = ctk.CTkButton(self.root,
                                     text="Login",
                                     width=100, 
                                     height=50,
                                     fg_color="#27ae60", 
                                     bg_color="#27ae60",
                                     font=("Arial", 20, "bold"),
                                     command=self.open_login_window)
        login_button.place(x=100, y=400)

        new_user_button = ctk.CTkButton(self.root,
                                        text="Sign Up",
                                        width=100, 
                                        height=50,
                                        fg_color="#27ae60", 
                                        bg_color="#27ae60",
                                        font=("Arial", 20, "bold"))
        new_user_button.place(x=300, y=400)

    def open_login_window(self):
        """Destroy current window and open login window."""
        from user_authentication.login.login_logic import LoginWindow  # Import here to avoid circular import
        self.root.destroy()
        LoginWindow()

    def run(self):
        """Start the main event loop."""
        self.root.mainloop()


if __name__ == "__main__":
    app = SecureScanApp()
    app.run()
