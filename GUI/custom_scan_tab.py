from PyQt6 import QtCore, QtGui, QtWidgets

class CustomScanTab(QtWidgets.QTabWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi()

    def setupUi(self):
        self.custom_scan_tab = QtWidgets.QWidget()
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.custom_scan_tab.sizePolicy().hasHeightForWidth())
        self.custom_scan_tab.setSizePolicy(sizePolicy)
        self.custom_scan_tab.setObjectName("custom_scan_tab")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.custom_scan_tab)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.custom_scan_left_frame = QtWidgets.QFrame(parent=self.custom_scan_tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.custom_scan_left_frame.sizePolicy().hasHeightForWidth())
        self.custom_scan_left_frame.setSizePolicy(sizePolicy)
        self.custom_scan_left_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.custom_scan_left_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.custom_scan_left_frame.setObjectName("custom_scan_left_frame")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.custom_scan_left_frame)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.custom_scan_label = QtWidgets.QLabel(parent=self.custom_scan_left_frame)
        self.custom_scan_label.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 50px;\n"
"    font-weight:bold;\n"
"}")
        self.custom_scan_label.setObjectName("custom_scan_label")
        self.verticalLayout_3.addWidget(self.custom_scan_label)
        self.url_horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.url_horizontalLayout_2.setContentsMargins(-1, 11, -1, -1)
        self.url_horizontalLayout_2.setObjectName("url_horizontalLayout_2")
        self.custom_scan_lineEdit = QtWidgets.QLineEdit(parent=self.custom_scan_left_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.custom_scan_lineEdit.sizePolicy().hasHeightForWidth())
        self.custom_scan_lineEdit.setSizePolicy(sizePolicy)
        self.custom_scan_lineEdit.setStyleSheet("QLineEdit {\n"
"    border: solid;\n"
"    border-radius: 18px;\n"
"    border-width: 0.5px;\n"
"    border-color: grey;\n"
"    padding-left: 20px;        \n"
"    padding-right: 20px;\n"
"    font-size:25px;\n"
"    padding-top: 10px;\n"
"    padding-bottom: 10px\n"
"}")
        self.custom_scan_lineEdit.setObjectName("custom_scan_lineEdit")
        self.url_horizontalLayout_2.addWidget(self.custom_scan_lineEdit)
        self.verticalLayout_3.addLayout(self.url_horizontalLayout_2)
        self.combo_box_horizontalLayout = QtWidgets.QHBoxLayout()
        self.combo_box_horizontalLayout.setContentsMargins(-1, 11, -1, -1)
        self.combo_box_horizontalLayout.setObjectName("combo_box_horizontalLayout")
        self.custom_scan_selector_comboBox = QtWidgets.QComboBox(parent=self.custom_scan_left_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.custom_scan_selector_comboBox.sizePolicy().hasHeightForWidth())
        self.custom_scan_selector_comboBox.setSizePolicy(sizePolicy)
        self.custom_scan_selector_comboBox.setFocusPolicy(QtCore.Qt.FocusPolicy.WheelFocus)
        self.custom_scan_selector_comboBox.setStyleSheet("QComboBox {\n"
"    background-color:rgb(35, 222, 104);\n"
"    color: white;\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.1px;\n"
"    transition: all 0.2s ease;\n"
"    font-size:25px;\n"
"    padding-top: 10px;\n"
"    padding-bottom: 10px;\n"
"    padding-left: 20px;\n"
"    padding-right:20px;\n"
"}\n"
"\n"
"QComboBox:hover {\n"
"    background-color: #27ae60;  /* Darker green */\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"    background-color: #1e8449;\n"
"    transform: scale(0.95);  /* Slight shrink effect */\n"
"}")
        self.custom_scan_selector_comboBox.setEditable(False)
        self.custom_scan_selector_comboBox.setObjectName("custom_scan_selector_comboBox")
        self.custom_scan_selector_comboBox.addItem("")
        self.custom_scan_selector_comboBox.addItem("")
        self.custom_scan_selector_comboBox.addItem("")
        self.custom_scan_selector_comboBox.addItem("")
        self.custom_scan_selector_comboBox.addItem("")
        self.combo_box_horizontalLayout.addWidget(self.custom_scan_selector_comboBox)
        self.verticalLayout_3.addLayout(self.combo_box_horizontalLayout)
        self.custom_scan_button_horizontalLayout = QtWidgets.QHBoxLayout()
        self.custom_scan_button_horizontalLayout.setContentsMargins(-1, 11, -1, -1)
        self.custom_scan_button_horizontalLayout.setObjectName("custom_scan_button_horizontalLayout")
        self.custom_scan_pushButton = QtWidgets.QPushButton(parent=self.custom_scan_left_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.custom_scan_pushButton.sizePolicy().hasHeightForWidth())
        self.custom_scan_pushButton.setSizePolicy(sizePolicy)
        self.custom_scan_pushButton.setStyleSheet("QPushButton {\n"
"    background-color:rgb(35, 222, 104);\n"
"    color: white;\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.1px;\n"
"    transition: all 0.2s ease;\n"
"    font-size:25px;\n"
"    font-weight:bold;\n"
"    padding: 10px 5px;\n"
"    padding-right: 30px;\n"
"    padding-left: 30px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: #27ae60;  /* Darker green */\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"    background-color: #1e8449;\n"
"    transform: scale(0.95);  /* Slight shrink effect */\n"
"}")
        self.custom_scan_pushButton.setObjectName("custom_scan_pushButton")
        self.custom_scan_button_horizontalLayout.addWidget(self.custom_scan_pushButton)
        self.verticalLayout_3.addLayout(self.custom_scan_button_horizontalLayout)
        self.custom_scan_output_textBrowser = QtWidgets.QTextBrowser(parent=self.custom_scan_left_frame)
        self.custom_scan_output_textBrowser.setObjectName("custom_scan_output_textBrowser")
        self.verticalLayout_3.addWidget(self.custom_scan_output_textBrowser)
        self.generate_detailed_report_horizontalLayout = QtWidgets.QHBoxLayout()
        self.generate_detailed_report_horizontalLayout.setContentsMargins(-1, 11, -1, -1)
        self.generate_detailed_report_horizontalLayout.setObjectName("generate_detailed_report_horizontalLayout")
        self.generate_custom_scan_report_pushButton = QtWidgets.QPushButton(parent=self.custom_scan_left_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.generate_custom_scan_report_pushButton.sizePolicy().hasHeightForWidth())
        self.generate_custom_scan_report_pushButton.setSizePolicy(sizePolicy)
        self.generate_custom_scan_report_pushButton.setStyleSheet("QPushButton {\n"
"    background-color:rgb(35, 222, 104);\n"
"    color: white;\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.1px;\n"
"    transition: all 0.2s ease;\n"
"    font-size:25px;\n"
"    font-weight:bold;\n"
"    padding-top: 10px;\n"
"    padding-bottom: 10px;\n"
"    padding-right: 30px;\n"
"    padding-left: 30px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: #27ae60;  /* Darker green */\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"    background-color: #1e8449;\n"
"    transform: scale(0.95);  /* Slight shrink effect */\n"
"}")
        self.generate_custom_scan_report_pushButton.setObjectName("generate_custom_scan_report_pushButton")
        self.generate_detailed_report_horizontalLayout.addWidget(self.generate_custom_scan_report_pushButton)
        self.verticalLayout_3.addLayout(self.generate_detailed_report_horizontalLayout)
        self.resest_scanner_Button_horizontalLayout = QtWidgets.QHBoxLayout()
        self.resest_scanner_Button_horizontalLayout.setContentsMargins(-1, 11, -1, -1)
        self.resest_scanner_Button_horizontalLayout.setObjectName("resest_scanner_Button_horizontalLayout")
        self.reset_scanner_pushButton = QtWidgets.QPushButton(parent=self.custom_scan_left_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.reset_scanner_pushButton.sizePolicy().hasHeightForWidth())
        self.reset_scanner_pushButton.setSizePolicy(sizePolicy)
        self.reset_scanner_pushButton.setStyleSheet("QPushButton {\n"
"    background-color:rgb(35, 222, 104);\n"
"    color: white;\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.1px;\n"
"    transition: all 0.2s ease;\n"
"    font-size:25px;\n"
"    font-weight:bold;\n"
"    padding-top: 10px;\n"
"    padding-bottom: 10px;\n"
"    padding-right: 30px;\n"
"    padding-left: 30px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: #27ae60;  /* Darker green */\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"    background-color: #1e8449;\n"
"    transform: scale(0.95);  /* Slight shrink effect */\n"
"}")
        self.reset_scanner_pushButton.setObjectName("reset_scanner_pushButton")
        self.resest_scanner_Button_horizontalLayout.addWidget(self.reset_scanner_pushButton)
        self.verticalLayout_3.addLayout(self.resest_scanner_Button_horizontalLayout)
        self.horizontalLayout_2.addWidget(self.custom_scan_left_frame)
        self.custom_scan_rightframe = QtWidgets.QFrame(parent=self.custom_scan_tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.custom_scan_rightframe.sizePolicy().hasHeightForWidth())
        self.custom_scan_rightframe.setSizePolicy(sizePolicy)
        self.custom_scan_rightframe.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.custom_scan_rightframe.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.custom_scan_rightframe.setObjectName("custom_scan_rightframe")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.custom_scan_rightframe)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.num_of_custom_scan_label = QtWidgets.QLabel(parent=self.custom_scan_rightframe)
        self.num_of_custom_scan_label.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 20px;\n"
"    font-weight:bold;\n"
"}")
        self.num_of_custom_scan_label.setObjectName("num_of_custom_scan_label")
        self.verticalLayout_4.addWidget(self.num_of_custom_scan_label)
        self.custom_scan_history_label = QtWidgets.QLabel(parent=self.custom_scan_rightframe)
        self.custom_scan_history_label.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 20px;\n"
"    font-weight:bold;\n"
"}")
        self.custom_scan_history_label.setObjectName("custom_scan_history_label")
        self.verticalLayout_4.addWidget(self.custom_scan_history_label)
        self.custom_scan_history_textBrowser = QtWidgets.QTextBrowser(parent=self.custom_scan_rightframe)
        self.custom_scan_history_textBrowser.setObjectName("custom_scan_history_textBrowser")
        self.verticalLayout_4.addWidget(self.custom_scan_history_textBrowser)
        self.view_custom_scan_history_button_horizontalLayout = QtWidgets.QHBoxLayout()
        self.view_custom_scan_history_button_horizontalLayout.setContentsMargins(-1, 11, -1, -1)
        self.view_custom_scan_history_button_horizontalLayout.setObjectName("view_custom_scan_history_button_horizontalLayout")
        self.view_custom_scan_history_pushButton_2 = QtWidgets.QPushButton(parent=self.custom_scan_rightframe)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.view_custom_scan_history_pushButton_2.sizePolicy().hasHeightForWidth())
        self.view_custom_scan_history_pushButton_2.setSizePolicy(sizePolicy)
        self.view_custom_scan_history_pushButton_2.setStyleSheet("QPushButton {\n"
"    background-color:rgb(35, 222, 104);\n"
"    color: white;\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.1px;\n"
"    transition: all 0.2s ease;\n"
"    font-size:25px;\n"
"    font-weight:bold;\n"
"    padding-top: 10px;\n"
"    padding-bottom: 10px;\n"
"    padding-right: 30px;\n"
"    padding-left: 30px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: #27ae60;  /* Darker green */\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"    background-color: #1e8449;\n"
"    transform: scale(0.95);  /* Slight shrink effect */\n"
"}")
        self.view_custom_scan_history_pushButton_2.setObjectName("view_custom_scan_history_pushButton_2")
        self.view_custom_scan_history_button_horizontalLayout.addWidget(self.view_custom_scan_history_pushButton_2)
        self.verticalLayout_4.addLayout(self.view_custom_scan_history_button_horizontalLayout)
        self.horizontalLayout_2.addWidget(self.custom_scan_rightframe)
        self.tabWidget.addTab(self.custom_scan_tab, "")
