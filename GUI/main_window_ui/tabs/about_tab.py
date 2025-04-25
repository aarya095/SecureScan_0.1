from PyQt6 import QtCore, QtGui, QtWidgets

class AboutTab(QtWidgets.QWidget):
    def __init__(self, parent=None, tab_widget=None):
        super().__init__(parent)
        self.tabWidget = tab_widget
        self.setupUi()

    def setupUi(self):
        # Main layout
        self.main_layout = QtWidgets.QVBoxLayout(self)

        # About App Label
        self.about_app_label = QtWidgets.QLabel("About this Application")
        self.about_app_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.about_app_label.setStyleSheet("font-size: 28px; font-weight: bold; margin-bottom: 10px;")
        self.main_layout.addWidget(self.about_app_label)

        # Scroll Area
        self.about_tab_scrollArea = QtWidgets.QScrollArea(self)
        self.about_tab_scrollArea.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding))
        self.about_tab_scrollArea.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.about_tab_scrollArea.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.about_tab_scrollArea.setWidgetResizable(True)
        self.main_layout.addWidget(self.about_tab_scrollArea)

        # Widget inside the scroll area
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.about_tab_scrollArea.setWidget(self.scrollAreaWidgetContents)

        # Layout for the scroll area content
        self.scroll_layout = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)

        # Load HTML file into a QTextEdit (set it to read-only for display purposes)
        self.html_viewer = QtWidgets.QTextEdit(self.scrollAreaWidgetContents)
        self.html_viewer.setReadOnly(True)
        self.html_viewer.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.NoTextInteraction)

        # Load HTML content (you can replace the filename with your own HTML file path)
        html_content = self.load_html_file("terms_and_conditions/about.html")
        self.html_viewer.setHtml(html_content)

        # Add the HTML viewer widget to the scroll area
        self.scroll_layout.addWidget(self.html_viewer)

    def load_html_file(self, file_path):
        """Load the HTML content from a file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except FileNotFoundError:
            return "<h2>Error: HTML file not found.</h2>"

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    window = QtWidgets.QMainWindow()
    history_tab = AboutTab()

    window.setCentralWidget(history_tab)
    window.setWindowTitle("Security Scanner")
    window.resize(1000, 600)
    window.show()
    sys.exit(app.exec())
