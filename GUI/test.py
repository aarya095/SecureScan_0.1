import customtkinter as ctk

app = ctk.CTk()
app.geometry("1000x1000")

# Create buttons
button1 = ctk.CTkButton(app, text="Button 1")
button2 = ctk.CTkButton(app, text="Button 2")
button3 = ctk.CTkButton(app, text="Button 3")

# Place buttons in the grid
button1.grid(row=0, column=0)
button2.grid(row=0, column=10)
button3.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

app.mainloop()
