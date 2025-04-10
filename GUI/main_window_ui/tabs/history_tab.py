from PyQt6 import QtCore, QtGui, QtWidgets
import tempfile
import os
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

class VulnerabilityPieChart(QtWidgets.QWidget):
    def __init__(self, vuln_data, parent=None):
        super().__init__(parent)
        self.vuln_data = vuln_data
        self.layout = QtWidgets.QVBoxLayout(self)
        self.canvas = FigureCanvas(Figure(figsize=(5, 4)))
        self.layout.addWidget(self.canvas)
        self.plot_chart()

    def plot_chart(self):
        labels = list(self.vuln_data.keys())
        sizes = list(self.vuln_data.values())
        total = sum(sizes)

        ax = self.canvas.figure.subplots()
        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            autopct='%1.1f%%',
            startangle=90,
            textprops=dict(color="white"),
            wedgeprops=dict(picker=True)  # <--- Enables picking!
        )
        ax.axis('equal')

        def on_pick(event):
            wedge = event.artist
            index = wedges.index(wedge)
            label = labels[index]
            value = sizes[index]
            ax.set_title(f"{label}: {value} ({(value/total)*100:.1f}%)")
            self.canvas.draw_idle()

        self.canvas.mpl_connect('pick_event', on_pick)


class HistoryTab(QtWidgets.QWidget):
    def __init__(self, parent=None, tab_widget=None):
        super().__init__(parent)
        self.tabWidget = tab_widget
        self.setupUi()

        from controller.Tabs_Controller.history_tab_controller import HistoryTabController
        self.controller = HistoryTabController(self)  
        self.controller.load_pie_chart_async()

    def setupUi(self):
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self)

        self.history_tab_frame = QtWidgets.QFrame(parent=self)
        self.history_tab_frame.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred)
        self.history_tab_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.history_tab_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)

        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.history_tab_frame)

        self.search_history_label = QtWidgets.QLabel("History", parent=self.history_tab_frame)
        self.verticalLayout_6.addWidget(self.search_history_label)

        self.horizontalLayout_main = QtWidgets.QHBoxLayout()
        self.verticalLayout_6.addLayout(self.horizontalLayout_main)

        self.pie_chart_container = QtWidgets.QVBoxLayout()
        self.horizontalLayout_main.addLayout(self.pie_chart_container)

        self.labels_container = QtWidgets.QVBoxLayout()

        self.total_num_scans_label = QtWidgets.QLabel("Total No. of Scans Performed: <count>", parent=self)
        self.total_num_scans_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.total_num_scans_label.setObjectName("headerLabel")

        self.total_num_vulnerabilities_label = QtWidgets.QLabel("Total Vulnerabilities Detected: <count>", parent=self)
        self.total_num_vulnerabilities_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.total_num_vulnerabilities_label.setObjectName("headerLabel")

        self.labels_container.addWidget(self.total_num_scans_label)
        self.labels_container.addWidget(self.total_num_vulnerabilities_label)

        self.horizontalLayout_main.addLayout(self.labels_container)

        self.verticalLayout_5.addWidget(self.history_tab_frame)

        self.frame_6 = QtWidgets.QFrame(parent=self)
        self.frame_6.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred))
        self.frame_6.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.frame_6.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)

        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.frame_6)

        self.view_full_scan_history_pushButton = QtWidgets.QPushButton("View Full Scan History", parent=self.frame_6)
        self.view_full_scan_history_pushButton.setMaximumWidth(500)
        self.view_full_scan_history_pushButton.setMinimumWidth(400)
        self.horizontalLayout_3.addWidget(self.view_full_scan_history_pushButton)

        self.view_custom_scan_history_pushButton = QtWidgets.QPushButton("View Custom Scan History", parent=self.frame_6)
        self.view_custom_scan_history_pushButton.setMaximumWidth(500)
        self.view_custom_scan_history_pushButton.setMinimumWidth(400)
        self.horizontalLayout_3.addWidget(self.view_custom_scan_history_pushButton)

        self.clear_history_comboBox = QtWidgets.QComboBox(parent=self.frame_6)
        self.clear_history_comboBox.addItems([
            "Delete Full Scan History",
            "Delete Custom Scan History",
            "Delete Everything"
        ])
        self.clear_history_comboBox.setMaximumWidth(500)
        self.clear_history_comboBox.setMinimumWidth(400)
        self.horizontalLayout_3.addWidget(self.clear_history_comboBox)

        self.verticalLayout_5.addWidget(self.frame_6)

        if self.tabWidget:
            self.tabWidget.addTab(self, "History")
            if self.tabWidget.currentWidget() != self:
                self.tabWidget.setCurrentWidget(self)
                print("History tab added successfully!")

    

    def display_pie_chart(self, vuln_counter):
        chart = VulnerabilityPieChart(vuln_counter, parent=self)

        while self.pie_chart_container.count():
            item = self.pie_chart_container.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)

        label = QtWidgets.QLabel("Vulnerability Distribution", parent=self)
        label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.pie_chart_container.addWidget(label)
        self.pie_chart_container.addWidget(chart)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    window = QtWidgets.QMainWindow()
    history_tab = HistoryTab()

    window.setCentralWidget(history_tab)
    window.setWindowTitle("Security Scanner")
    window.resize(1000, 600)
    window.show()
    sys.exit(app.exec())
