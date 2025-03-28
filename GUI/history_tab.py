from PyQt6 import QtCore, QtGui, QtWidgets

class HistoryTab(QtWidgets.QTabWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi()

    def setupUi(self):
        #History Tab
        self.history_tab = QtWidgets.QWidget()
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.history_tab.sizePolicy().hasHeightForWidth())
        self.history_tab.setSizePolicy(sizePolicy)
        self.history_tab.setObjectName("history_tab")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.history_tab)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.history_tab_frame = QtWidgets.QFrame(parent=self.history_tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.history_tab_frame.sizePolicy().hasHeightForWidth())
        self.history_tab_frame.setSizePolicy(sizePolicy)
        self.history_tab_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.history_tab_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.history_tab_frame.setObjectName("history_tab_frame")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.history_tab_frame)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.search_history_label = QtWidgets.QLabel(parent=self.history_tab_frame)
        self.search_history_label.setStyleSheet("QLabel{\n"
"    color:black;\n"
"    font-size: 30px;\n"
"    font-weight:bold;\n"
"}")
        self.search_history_label.setObjectName("search_history_label")
        self.verticalLayout_6.addWidget(self.search_history_label)
        self.search_history_lineEdit = QtWidgets.QLineEdit(parent=self.history_tab_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.search_history_lineEdit.sizePolicy().hasHeightForWidth())
        self.search_history_lineEdit.setSizePolicy(sizePolicy)
        self.search_history_lineEdit.setStyleSheet("QLineEdit {\n"
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
        self.search_history_lineEdit.setObjectName("search_history_lineEdit")
        self.verticalLayout_6.addWidget(self.search_history_lineEdit)
        self.past_scans_displaying_textBrowser = QtWidgets.QTextBrowser(parent=self.history_tab_frame)
        self.past_scans_displaying_textBrowser.setObjectName("past_scans_displaying_textBrowser")
        self.verticalLayout_6.addWidget(self.past_scans_displaying_textBrowser)
        self.verticalLayout_5.addWidget(self.history_tab_frame)
        self.frame_6 = QtWidgets.QFrame(parent=self.history_tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frame_6.sizePolicy().hasHeightForWidth())
        self.frame_6.setSizePolicy(sizePolicy)
        self.frame_6.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.frame_6.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.frame_6.setObjectName("frame_6")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.frame_6)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.view_full_scan_history_pushButton = QtWidgets.QPushButton(parent=self.frame_6)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.view_full_scan_history_pushButton.sizePolicy().hasHeightForWidth())
        self.view_full_scan_history_pushButton.setSizePolicy(sizePolicy)
        self.view_full_scan_history_pushButton.setStyleSheet("QPushButton {\n"
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
        self.view_full_scan_history_pushButton.setObjectName("view_full_scan_history_pushButton")
        self.horizontalLayout_3.addWidget(self.view_full_scan_history_pushButton)
        self.view_custom_scan_history_pushButton = QtWidgets.QPushButton(parent=self.frame_6)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.view_custom_scan_history_pushButton.sizePolicy().hasHeightForWidth())
        self.view_custom_scan_history_pushButton.setSizePolicy(sizePolicy)
        self.view_custom_scan_history_pushButton.setStyleSheet("QPushButton {\n"
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
        self.view_custom_scan_history_pushButton.setObjectName("view_custom_scan_history_pushButton")
        self.horizontalLayout_3.addWidget(self.view_custom_scan_history_pushButton)
        self.clear_history_comboBox = QtWidgets.QComboBox(parent=self.frame_6)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.clear_history_comboBox.sizePolicy().hasHeightForWidth())
        self.clear_history_comboBox.setSizePolicy(sizePolicy)
        self.clear_history_comboBox.setStyleSheet("QComboBox {\n"
"    background-color:rgb(35, 222, 104);\n"
"    color: white;\n"
"    border: solid;\n"
"    border-radius: 20px;\n"
"    border-width: 0.1px;\n"
"    transition: all 0.2s ease;\n"
"    font-size:25px;\n"
"    font-weight: bold;\n"
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
        self.clear_history_comboBox.setEditable(False)
        self.clear_history_comboBox.setMaxVisibleItems(3)
        self.clear_history_comboBox.setObjectName("clear_history_comboBox")
        self.clear_history_comboBox.addItem("")
        self.clear_history_comboBox.addItem("")
        self.clear_history_comboBox.addItem("")
        self.horizontalLayout_3.addWidget(self.clear_history_comboBox)
        self.verticalLayout_5.addWidget(self.frame_6)
        self.tabWidget.addTab(self.history_tab, "")
