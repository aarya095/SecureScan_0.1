import os
import subprocess
import time
from website_manager.utils import is_server_running

def get_website_path(website_name):
    return os.path.join("vulnerable_websites", website_name)

def start_website(website_name, port):
    """Starts the website's server."""
    website_path = get_website_path(website_name)

    if not os.path.exists(website_path):
        print(f"❌ Website '{website_name}' not found!")
        return False

    os.chdir(website_path)  # Change to website directory
    process = None

    if os.path.exists("server.js"):
        print("🚀 Starting Node.js server...")
        process = subprocess.Popen(["node", "server.js"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    elif os.path.exists("server.py"):
        print("🚀 Starting Python Flask/Django server...")
        process = subprocess.Popen(["python", "server.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        print("❌ No recognized server file found (server.js or server.py).")
        return False

    # Wait a few seconds to ensure the server starts properly
    time.sleep(5)

    if is_server_running(port):
        print(f"✅ {website_name} started successfully on port {port}.")
        return process
    else:
        print(f"❌ Failed to start {website_name}.")
        return None

def stop_website(process, website_name):
    """Stops the website's server."""
    if process:
        process.terminate()
        process.wait()
        print(f"🛑 {website_name} has been stopped.")
    else:
        print(f"⚠️ No process found for {website_name}. Trying to find and kill the process manually...")
        subprocess.run(["taskkill", "/F", "/IM", "node.exe"], capture_output=True, text=True)
        subprocess.run(["taskkill", "/F", "/IM", "python.exe"], capture_output=True, text=True)

def restart_website(website_name, port):
    """Restarts the website's server if it's not running."""
    if not is_server_running(port):
        print(f"⚠️ Server for {website_name} is down. Restarting...")
        return start_website(website_name, port)
    else:
        print(f"✅ {website_name} is already running.")
        return None
