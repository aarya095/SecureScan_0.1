# GUI/terms_dialog.py

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextBrowser, QPushButton
from PyQt6.QtCore import QFile, QTextStream
import os


class TermsDialog(QDialog):
    def __init__(self, parent=None, filepath="terms_and_conditions/terms_privacy_notice.txt"):
        super().__init__(parent)
        self.setWindowTitle("Terms and Conditions")
        self.resize(600, 500)

        layout = QVBoxLayout()

        self.text_browser = QTextBrowser()
        layout.addWidget(self.text_browser)

        self.ok_button = QPushButton("Close")
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(self.ok_button)

        self.setLayout(layout)

        self.load_terms(filepath)

    def load_terms(self, filepath):
        if not os.path.exists(filepath):
            self.text_browser.setText("⚠️ Terms and Conditions file not found.")
            return

        with open(filepath, "r", encoding="utf-8") as file:
            content = file.read()
            if filepath.endswith(".html"):
                self.text_browser.setHtml(content)
            else:
                self.text_browser.setPlainText(content)
