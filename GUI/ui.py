import customtkinter as ctk

# Set UI theme
ctk.set_appearance_mode("dark")  
ctk.set_default_color_theme("green")  

# Create the main window
root = ctk.CTk()
root.geometry("400x300")

# Function for button click
def on_click():
    print("Glass Button Clicked!")


# Create the glassmorphic button using a tuple for transparency
glass_button = ctk.CTkButton(
    root, 
    text="Glass Button", 
    width=160, 
    height=50,
    corner_radius=25,   # Smooth rounded edges
    fg_color=("white", "gray20"),  # Light mode: White, Dark mode: Dark gray
    hover_color=("lightgray", "gray30"),  # Light mode: Light gray, Dark mode: Slightly darker gray
    border_width=2,      # Subtle border
    border_color="white", 
    text_color="white",   # Bright text for contrast
    command=on_click
)
glass_button.place(x=120, y=125)  # Placed slightly above the shadow

root.mainloop()
