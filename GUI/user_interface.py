from PyQt6 import QtCore, QtGui, QtWidgets
from home_quick_scan import QuickScanTab
from custom_scan_tab import CustomScanTab
from history_tab import HistoryTab
from profile_tab import ProfileTab
from about_tab import AboutTab

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1221, 770)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setStyleSheet("QMainWindow{\n"
"    background-color:black\n"
"}")
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.centralwidget.sizePolicy().hasHeightForWidth())
        self.centralwidget.setSizePolicy(sizePolicy)

        self.tabWidget = QtWidgets.QTabWidget(parent=self.centralwidget)
        layout = QtWidgets.QVBoxLayout(self.centralwidget)  # Use vertical layout
        layout.addWidget(self.tabWidget)
        MainWindow.setCentralWidget(self.centralwidget)  
        self.tabWidget.setObjectName("tabWidget")

        self.home_tab = QuickScanTab(parent=self.tabWidget)
        self.custom_scan_tab = CustomScanTab(parent=self.tabWidget)
        self.history_tab = HistoryTab(parent=self.tabWidget)
        self.profile_tab = ProfileTab(parent=self.tabWidget)
        self.about_tab = AboutTab(parent=self.tabWidget)

        # Add them to the tab widget
        self.tabWidget.addTab(self.home_tab, "Home")
        self.tabWidget.addTab(self.custom_scan_tab, "Custom Scan")
        self.tabWidget.addTab(self.history_tab, "History")
        self.tabWidget.addTab(self.profile_tab, "Profile")
        self.tabWidget.addTab(self.about_tab, "About")

        MainWindow.setCentralWidget(self.centralwidget)

        self.tabWidget.setCurrentIndex(0)
        print("Total Tabs:", self.tabWidget.count())
        
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        
    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "SecureScan"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)

    # 🔹 Apply Light Theme (Method 1: QPalette)
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.ColorRole.Window, QtGui.QColor(255, 255, 255))  # White background
    palette.setColor(QtGui.QPalette.ColorRole.WindowText, QtGui.QColor(0, 0, 0))  # Black text
    palette.setColor(QtGui.QPalette.ColorRole.Base, QtGui.QColor(240, 240, 240))  # Input fields
    palette.setColor(QtGui.QPalette.ColorRole.Text, QtGui.QColor(0, 0, 0))  # Text color
    palette.setColor(QtGui.QPalette.ColorRole.Button, QtGui.QColor(230, 230, 230))  # Button background
    palette.setColor(QtGui.QPalette.ColorRole.ButtonText, QtGui.QColor(0, 0, 0))  # Button text

    app.setPalette(palette)

    # 🔹 Apply Light Theme Stylesheet (Method 2: Stylesheet)
    app.setStyleSheet("""
        QWidget {
            background-color: white;
            color: black;
        }
        QPushButton {
            background-color: #f0f0f0;
            color: black;
            border: 1px solid #bfbfbf;
            border-radius: 5px;
            padding: 5px;
        }
        QPushButton:hover {
            background-color: #e0e0e0;
        }
        QLineEdit {
            background-color: white;
            border: 1px solid #bfbfbf;
            border-radius: 5px;
            padding: 5px;
        }
    """)

    # 🔹 Initialize Main Window
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())