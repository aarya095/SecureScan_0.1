import tkinter as tk
from tkinter import messagebox

def on_entry_click(event):
    if url_entry.get() == placeholder_text:
        url_entry.delete(0, tk.END)
        url_entry.config(fg="white")

def on_focus_out(event):
    if not url_entry.get():
        url_entry.insert(0, placeholder_text)
        url_entry.config(fg="gray")

def anaylze_url():
    url = url_entry.get()
    if url == placeholder_text or url.strip() == "":
        messagebox.showwarning("warning","Please enter a valid URL!")
    else:
        messagebox.showinfo("Analyzing",f"Analyzing: {url}")

root = tk.Tk()
root.title("Home")
root.geometry("700x500+450+150")
root.config(bg="#1B1B1B")

title_label = tk.Label(root, text="URL Anaylzer", 
                       font=("Arial", 20, "bold"),
                       fg="white", bg="#16A085")
title_label.place(x=250, y=30)

placeholder_text = "Enter URL here..."
url_font = ("Verdana",15)

url_entry = tk.Entry(root, width=30, font=url_font,
                     fg="gray",bd=2,relief="solid",
                     insertbackground="white")
url_entry.insert(0, placeholder_text)
url_entry.bind("<FocusIn>",on_entry_click)
url_entry.bind("<FocusOut>",on_focus_out)
url_entry.place(x=150, y=100)

def on_hover(event):
    scan_button.config(bg="#1ABC9C")

def on_leave(event):
    scan_button.config(bg="#16A085")

scan_button_font = ("Arial",15,"bold")
scan_button = tk.Button(root, text="Analyze",
                        fg="white", bg="#16A085",font=scan_button_font,
                        width=15, height=1, bd=3, relief="raised",
                        command=anaylze_url)
scan_button.place(x=250,y=160)

scan_button.bind("<Enter>", on_hover)
scan_button.bind("<Leave>", on_leave)

root.mainloop()