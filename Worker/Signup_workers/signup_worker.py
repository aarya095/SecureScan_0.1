from PyQt6.QtCore import pyqtSignal, QObject
from user_authentication.signup.signup_logic import SignupLogic

class SignupWorker(QObject):
    result_ready = pyqtSignal(bool)  
    error = pyqtSignal(str) 
    
    def __init__(self, username, email, password, confirm_password):
        super().__init__()
        self.username = username
        self.email = email
        self.password = password
        self.confirm_password = confirm_password

    def run(self):
        try:
            signup_logic = SignupLogic()
            success, message = signup_logic.register_user(self.username, self.email, self.password, self.confirm_password)
            
            if success:
                self.result_ready.emit(True)
            else:
                self.error.emit(message) 

        except Exception as e:
            self.error.emit(str(e))