import subprocess
import time
import os

# Global variable to store the process
server_process = None

def start_server():
    """Start the Node.js server using nodemon."""
    global server_process
    if server_process is None:
        command = "cmd /k cd /d D:\\Aarya\\Coding_Projects\\websites_for_scanning_js\\web-1 && nodemon server.js"
        server_process = subprocess.Popen(command, shell=True)
        print("🚀 Server started successfully!")
    else:
        print("⚠️ Server is already running!")

def stop_server():
    """Stop the running server process."""
    global server_process
    if server_process is not None:
        server_process.terminate()  # Send termination signal
        server_process = None
        print("🛑 Server stopped.")
    else:
        print("⚠️ No server is running.")

def restart_server():
    """Restart the server process."""
    stop_server()
    time.sleep(2)  # Wait for 2 seconds before restarting
    start_server()

# Example usage:
start_server()  # Start the server
time.sleep(10)  # Wait for 10 seconds (simulate some activity)
stop_server()  # Stop the server
