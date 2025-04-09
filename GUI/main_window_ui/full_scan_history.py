from PyQt6 import QtCore, QtGui, QtWidgets

class FullScanHistoryWindow(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()
        self.setupUi()

    def setupUi(self):
        self.setObjectName("MainWindow")
        self.resize(1099, 693)
        self.setMinimumSize(1099, 693)
        
        # Create central widget and layout
        self.centralwidget = QtWidgets.QWidget(parent=self)
        self.setCentralWidget(self.centralwidget)
        
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")

        # Frame for header and buttons
        self.frame = QtWidgets.QFrame(parent=self.centralwidget)
        self.frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.frame.setObjectName("frame")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.frame)
        self.horizontalLayout.setObjectName("horizontalLayout")

        # Label for "Custom Scan History"
        self.custom_scan_history_label = QtWidgets.QLabel(parent=self.frame)
        self.custom_scan_history_label.setObjectName("custom_scan_history_label")
        self.custom_scan_history_label.setText("Custom Scan History")  # Set text directly here
        self.horizontalLayout.addWidget(self.custom_scan_history_label)

        # Spacer item for layout alignment
        spacerItem = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout.addItem(spacerItem)

        # Button for deleting history
        self.delete_history_pushButton = QtWidgets.QPushButton(parent=self.frame)
        self.delete_history_pushButton.setObjectName("delete_history_pushButton")
        self.delete_history_pushButton.setText("Delete History")  # Set text directly here
        self.horizontalLayout.addWidget(self.delete_history_pushButton)

        self.verticalLayout.addWidget(self.frame)
        self.verticalLayout.setStretch(1, 1)

        # Frame for table
        self.frame_2 = QtWidgets.QFrame(parent=self.centralwidget)
        self.frame_2.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.frame_2.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.frame_2.setObjectName("frame_2")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.frame_2)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")

        # Table for scan history
        self.custom_scan_history_tableWidget = QtWidgets.QTableWidget(parent=self.frame_2)
        self.custom_scan_history_tableWidget.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.custom_scan_history_tableWidget.setLayoutDirection(QtCore.Qt.LayoutDirection.LeftToRight)
        self.custom_scan_history_tableWidget.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.custom_scan_history_tableWidget.setAlternatingRowColors(False)
        self.custom_scan_history_tableWidget.setGridStyle(QtCore.Qt.PenStyle.DashLine)
        self.custom_scan_history_tableWidget.setObjectName("custom_scan_history_tableWidget")
        self.custom_scan_history_tableWidget.setColumnCount(6)  # Increase column count to 6 (5 data columns + 1 button column)
        self.custom_scan_history_tableWidget.setRowCount(0)

        # Setting headers for the columns directly
        self.custom_scan_history_tableWidget.setHorizontalHeaderItem(0, QtWidgets.QTableWidgetItem("Sr. No."))
        self.custom_scan_history_tableWidget.setHorizontalHeaderItem(1, QtWidgets.QTableWidgetItem("Scan Date and Time"))
        self.custom_scan_history_tableWidget.setHorizontalHeaderItem(2, QtWidgets.QTableWidgetItem("Website URL"))
        self.custom_scan_history_tableWidget.setHorizontalHeaderItem(3, QtWidgets.QTableWidgetItem("Execution Time"))
        self.custom_scan_history_tableWidget.setHorizontalHeaderItem(4, QtWidgets.QTableWidgetItem("Vulnerabilities Detected"))
        self.custom_scan_history_tableWidget.setHorizontalHeaderItem(5, QtWidgets.QTableWidgetItem("View PDF"))  # Add new header for PDF column

        # Set the table to resize columns proportionally with window resizing
        header = self.custom_scan_history_tableWidget.horizontalHeader()
        header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Stretch)  # This ensures the columns stretch with the window

        # Set the table's size policy to expand and fill the space
        self.custom_scan_history_tableWidget.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)

        # Example scan history data (you can replace this with your actual data)
        scan_history = [
            {'timestamp': '2025-04-09 12:30:00', 'url': 'http://example.com', 'execution_time': '2 minutes'},
            {'timestamp': '2025-04-09 14:00:00', 'url': 'http://anotherurl.com', 'execution_time': '5 minutes'}
        ]

        # Populate the table with scan data
        for row, scan in enumerate(scan_history):
            self.custom_scan_history_tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(str(row + 1)))  # Sr. No.
            self.custom_scan_history_tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(scan['timestamp']))  # Scan Date and Time
            self.custom_scan_history_tableWidget.setItem(row, 2, QtWidgets.QTableWidgetItem(scan['url']))  # Website URL
            self.custom_scan_history_tableWidget.setItem(row, 3, QtWidgets.QTableWidgetItem(scan['execution_time']))  # Execution Time
            self.custom_scan_history_tableWidget.setItem(row, 4, QtWidgets.QTableWidgetItem("N/A"))  # Vulnerabilities Detected (dummy data)

            # Add a "View PDF" button to the last column
            view_pdf_button = QtWidgets.QPushButton("View PDF")
            view_pdf_button.clicked.connect(lambda checked, scan=scan: self.view_pdf(scan))
            self.custom_scan_history_tableWidget.setCellWidget(row, 5, view_pdf_button)  # View PDF button

        # Adding table to the layout
        self.horizontalLayout_2.addWidget(self.custom_scan_history_tableWidget)
        self.horizontalLayout_2.setStretch(0, 1)
        self.verticalLayout.addWidget(self.frame_2)

    def view_pdf(self, scan):
        # Simulate opening the PDF (you would implement real PDF viewing functionality here)
        print(f"Opening PDF for scan at {scan['timestamp']}...")

    @staticmethod
    def load_stylesheet(file_path):
        
        try:
            with open(file_path, "r") as f:
                return f.read()
        except FileNotFoundError:
            print(f"Warning: Stylesheet '{file_path}' not found.")
            return ""

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    stylesheet = FullScanHistoryWindow.load_stylesheet("GUI/theme_switch/dark_style.qss")
    app.setStyleSheet(stylesheet)
    MainWindow = FullScanHistoryWindow()
    MainWindow.show()
    sys.exit(app.exec())
