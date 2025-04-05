import sys
from PyQt6.QtWidgets import QApplication
from GUI.log_in.login_gui import LoginWindow
from controller.Login_controller.login_controller import LoginController

def main():
    try:
        app = QApplication(sys.argv)
        login_view = LoginWindow()
        login_controller = LoginController(login_view)

        login_view.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"App crashed with error: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    login_view = LoginWindow()
    login_controller = LoginController(login_view)

    # 👇 Connect controller to view
    login_view.controller = login_controller

    login_view.show()
    sys.exit(app.exec())
