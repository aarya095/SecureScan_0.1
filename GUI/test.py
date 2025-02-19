import customtkinter as ctk

# Initialize main app
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Vertical Tabs (Stacked) with CustomTkinter")
app.geometry("500x400")

# Configure grid layout
app.grid_rowconfigure((0, 1, 2), weight=1)  # Allow vertical expansion for buttons
app.grid_columnconfigure(1, weight=1)  # Allow content expansion

# Function to switch tabs
def show_frame(tab_name):
    for frame in frames.values():
        frame.grid_remove()  # Hide all frames
    frames[tab_name].grid(row=0, column=1, rowspan=3, sticky="nsew")  # Show selected tab

# Create tab buttons (stacked vertically)
tab_buttons = {
    "Tab 1": ctk.CTkButton(app, text="Tab 1", command=lambda: show_frame("Tab1")),
    "Tab 2": ctk.CTkButton(app, text="Tab 2", command=lambda: show_frame("Tab2")),
    "Tab 3": ctk.CTkButton(app, text="Tab 3", command=lambda: show_frame("Tab3")),
}

for i, button in enumerate(tab_buttons.values()):
    button.grid(row=i, column=0, padx=10, pady=5, sticky="ew")  # Stack buttons vertically

# Create tab content frames
frames = {
    "Tab1": ctk.CTkFrame(app, fg_color="lightblue"),
    "Tab2": ctk.CTkFrame(app, fg_color="lightgreen"),
    "Tab3": ctk.CTkFrame(app, fg_color="lightcoral"),
}

# Add labels to each frame
for tab_name, frame in frames.items():
    label = ctk.CTkLabel(frame, text=f"{tab_name} Content", font=("Arial", 20))
    label.pack(pady=20)

# Show the first tab by default
show_frame("Tab1")

# Run the application
app.mainloop()
