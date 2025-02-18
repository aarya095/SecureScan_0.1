import json
import customtkinter as ctk

def load_results(filename="url_security_status.json"):
    """Load test results from the JSON file."""
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return {"Error": {"message": str(e)}}

def display_results():
    """Create a GUI to display security test results dynamically."""
    data = load_results()

    # Create the main window
    root = ctk.CTk()
    root.title("Security Test Results")
    root.geometry("900x600")
    root.configure(bg="#2E2E2E")  # Dark mode background

    # Create a frame for scrolling
    frame = ctk.CTkFrame(root)
    frame.pack(expand=True, fill="both", padx=20, pady=20)

    # Create a title label
    title = ctk.CTkLabel(frame, text="Security Test Results", font=("Arial", 22, "bold"))
    title.pack(pady=10)

    # Iterate through results and dynamically create UI elements
    for url, test_results in data.items():
        # Create a collapsible section for each URL
        url_label = ctk.CTkLabel(frame, text=url, font=("Arial", 18, "bold"), fg_color="#333", text_color="white", corner_radius=5)
        url_label.pack(fill="x", pady=5)

        for test_name, result in test_results.items():
            result_text = f"{test_name}: {result}"  # Default as text
            text_color = "green" if result in [True, "Secure", "Passed"] else "red"

            # Handle different result formats
            if isinstance(result, bool):
                result_text = f"{test_name}: {'✅ Pass' if result else '❌ Fail'}"
            elif isinstance(result, dict):
                result_text = f"{test_name}: (See details)"
            elif isinstance(result, list):
                result_text = f"{test_name}: {', '.join(result)}"

            # Display test result
            label = ctk.CTkLabel(frame, text=result_text, font=("Arial", 14), text_color=text_color)
            label.pack(anchor="w", padx=20)

    # Run the Tkinter event loop
    root.mainloop()

if __name__ == "__main__":
    display_results()
