from PyQt6 import QtCore, QtGui, QtWidgets

class HistoryTab(QtWidgets.QWidget):
    def __init__(self, parent=None, tab_widget=None):
        super().__init__(parent)
        self.tabWidget = tab_widget
        self.setupUi()

    def setupUi(self):
        # History Tab
        self.history_tab = QtWidgets.QWidget(parent=self)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        self.history_tab.setSizePolicy(sizePolicy)
        self.history_tab.setObjectName("history_tab")

        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.history_tab)

        # History Tab Frame
        self.history_tab_frame = QtWidgets.QFrame(parent=self.history_tab)  # ✅ FIX: Added parent
        self.history_tab_frame.setSizePolicy(sizePolicy)
        self.history_tab_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.history_tab_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)

        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.history_tab_frame)

        # Search History Label
        self.search_history_label = QtWidgets.QLabel("Search History", parent=self.history_tab_frame)
        self.search_history_label.setStyleSheet(self.get_label_style())
        self.verticalLayout_6.addWidget(self.search_history_label)

        # Search History Input
        self.search_history_lineEdit = QtWidgets.QLineEdit(parent=self.history_tab_frame)
        self.search_history_lineEdit.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed))
        self.search_history_lineEdit.setPlaceholderText("Enter URL")
        self.search_history_lineEdit.setStyleSheet(self.get_input_style())
        self.verticalLayout_6.addWidget(self.search_history_lineEdit)

        # Past Scans Display
        self.past_scans_displaying_textBrowser = QtWidgets.QTextBrowser(parent=self.history_tab_frame)
        self.verticalLayout_6.addWidget(self.past_scans_displaying_textBrowser)

        self.verticalLayout_5.addWidget(self.history_tab_frame)

        # Bottom Frame (Buttons and ComboBox)
        self.frame_6 = QtWidgets.QFrame(parent=self.history_tab)
        self.frame_6.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred))
        self.frame_6.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.frame_6.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)

        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.frame_6)

        # View Full Scan History Button
        self.view_full_scan_history_pushButton = QtWidgets.QPushButton("View Full Scan History", parent=self.frame_6)
        self.view_full_scan_history_pushButton.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed))
        self.view_full_scan_history_pushButton.setStyleSheet(self.get_button_style())
        self.horizontalLayout_3.addWidget(self.view_full_scan_history_pushButton)

        # View Custom Scan History Button
        self.view_custom_scan_history_pushButton = QtWidgets.QPushButton("View Custom Scan History", parent=self.frame_6)
        self.view_custom_scan_history_pushButton.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed))
        self.view_custom_scan_history_pushButton.setStyleSheet(self.get_button_style())
        self.horizontalLayout_3.addWidget(self.view_custom_scan_history_pushButton)

        # Clear History ComboBox
        self.clear_history_comboBox = QtWidgets.QComboBox(parent=self.frame_6)
        self.clear_history_comboBox.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed))
        self.clear_history_comboBox.setStyleSheet(self.get_combo_box_style())
        self.clear_history_comboBox.addItems([
            "Delete Full Scan History",
            "Delete Custom Scan History",
            "Delete Everything"
        ])
        self.horizontalLayout_3.addWidget(self.clear_history_comboBox)

        self.verticalLayout_5.addWidget(self.frame_6)

        # Add tab to tab widget if available
        if self.tabWidget:
            self.tabWidget.addTab(self, "History")
            if self.tabWidget.currentWidget() != self:  # ✅ Avoid unnecessary function calls
                self.tabWidget.setCurrentWidget(self)
            print("History tab added successfully!")

    def get_button_style(self):
        """ Returns common button style """
        return """
            QPushButton {
                background-color: rgb(35, 222, 104);
                color: white;
                border: solid;
                border-radius: 20px;
                border-width: 0.1px;
                transition: all 0.2s ease;
                font-size: 25px;
                font-weight: bold;
                padding: 10px 5px;
                padding-right: 30px;
                padding-left: 30px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
            QPushButton:pressed {
                background-color: #1e8449;
                transform: scale(0.95);
            }
        """

    def get_combo_box_style(self):
        """ Returns common combo box style """
        return """
            QComboBox {
                background-color: rgb(35, 222, 104);
                color: white;
                border: solid;
                border-radius: 20px;
                border-width: 0.1px;
                transition: all 0.2s ease;
                font-size: 25px;
                font-weight: bold;
                padding-top: 10px;
                padding-bottom: 10px;
                padding-left: 20px;
                padding-right: 20px;
            }
            QComboBox:hover {
                background-color: #27ae60;
            }
            QPushButton:pressed {
                background-color: #1e8449;
                transform: scale(0.95);
            }
        """

    def get_label_style(self):
        """ Returns common label style """
        return """
            QLabel {
                color: black;
                font-size: 30px;
                font-weight: bold;
            }
        """

    def get_input_style(self):
        """ Returns common input field style """
        return """
            QLineEdit {
                border: solid;
                border-radius: 18px;
                border-width: 0.5px;
                border-color: grey;
                padding-left: 20px;
                padding-right: 20px;
                font-size: 25px;
                padding-top: 10px;
                padding-bottom: 10px;
            }
        """
