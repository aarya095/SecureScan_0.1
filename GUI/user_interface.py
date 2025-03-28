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
        self.tabWidget.setGeometry(QtCore.QRect(10, 10, 1200, 700))  # Set size and position
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

        self.tabWidget.setCurrentIndex(4)
        
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        
    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "SecureScan"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())
