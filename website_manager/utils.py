import subprocess

def is_server_running(port):
    """Check if a server is running on a given port."""
    result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
    return f":{port}" in result.stdout
