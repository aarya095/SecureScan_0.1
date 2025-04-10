import sys
from PyQt6.QtWidgets import QApplication
from GUI.log_in.login_gui import LoginWindow
from controller.Login_controller.login_controller import LoginController
from GUI.main_window_ui.user_interface import Ui_MainWindow

def main():
    try:
        app = QApplication(sys.argv)
        
        login_view = LoginWindow()
        login_controller = LoginController(login_view)
        login_view.controller = login_controller

        login_view.show()

        app.exec()

        if login_view.login_successful:  # you should set this flag from your controller
            with open("styles/main.qss", "r") as f:
                app.setStyleSheet(f.read())

            main_window = Ui_MainWindow()
            main_window.show()
            sys.exit(app.exec())

    except Exception as e:
        print(f"App crashed with error: {e}")

if __name__ == "__main__":
    main()
