from PyQt6 import QtCore, QtGui, QtWidgets

class HistoryTab(QtWidgets.QWidget):
    def __init__(self, parent=None, tab_widget=None):
        super().__init__(parent)
        self.tabWidget = tab_widget
        self.setupUi()

    def setupUi(self):
        
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self)

        # History Tab Frame
        self.history_tab_frame = QtWidgets.QFrame(parent=self)
        self.history_tab_frame.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred)
        self.history_tab_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.history_tab_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)

        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.history_tab_frame)

        # Search History Label
        self.search_history_label = QtWidgets.QLabel("Search History", parent=self.history_tab_frame)
        self.verticalLayout_6.addWidget(self.search_history_label)

        # Search History Input
        self.search_history_lineEdit = QtWidgets.QLineEdit(parent=self.history_tab_frame)
        self.search_history_lineEdit.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed))
        self.search_history_lineEdit.setPlaceholderText("Enter URL")
        self.verticalLayout_6.addWidget(self.search_history_lineEdit)

        # Past Scans Display
        self.past_scans_displaying_textBrowser = QtWidgets.QTextBrowser(parent=self.history_tab_frame)
        self.verticalLayout_6.addWidget(self.past_scans_displaying_textBrowser)

        self.verticalLayout_5.addWidget(self.history_tab_frame)

        # Bottom Frame (Buttons and ComboBox)
        self.frame_6 = QtWidgets.QFrame(parent=self)
        self.frame_6.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred))
        self.frame_6.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.frame_6.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)

        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.frame_6)

        # View Full Scan History Button
        self.view_full_scan_history_pushButton = QtWidgets.QPushButton("View Full Scan History", parent=self.frame_6)
        self.view_full_scan_history_pushButton.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed))
        self.horizontalLayout_3.addWidget(self.view_full_scan_history_pushButton)

        # View Custom Scan History Button
        self.view_custom_scan_history_pushButton = QtWidgets.QPushButton("View Custom Scan History", parent=self.frame_6)
        self.view_custom_scan_history_pushButton.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed))
        self.horizontalLayout_3.addWidget(self.view_custom_scan_history_pushButton)

        # Clear History ComboBox
        self.clear_history_comboBox = QtWidgets.QComboBox(parent=self.frame_6)
        self.clear_history_comboBox.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed))
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

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

class VulnerabilityPieChart(FigureCanvas):
    def __init__(self, vuln_data, parent=None):
        self.fig = Figure(figsize=(5, 5))
        super().__init__(self.fig)
        self.setParent(parent)
        self.plot_chart(vuln_data)

    def plot_chart(self, vuln_data):
        ax = self.fig.add_subplot(111)
        labels = list(vuln_data.keys())
        sizes = list(vuln_data.values())

        if not sizes:
            ax.text(0.5, 0.5, "No Data Available", horizontalalignment='center', verticalalignment='center', transform=ax.transAxes)
            return

        colors = ['#FF6F61', '#6B5B95', '#88B04B', '#F7CAC9', '#92A8D1']
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=colors)
        ax.axis('equal')  # Equal aspect ratio to make it a circle
        self.draw()
