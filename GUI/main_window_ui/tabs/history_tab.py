from PyQt6 import QtCore, QtGui, QtWidgets
import plotly.graph_objects as go
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl
import tempfile
import os

class VulnerabilityPieChart(QWebEngineView):
    def __init__(self, vuln_data, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(400)
        self.setMinimumWidth(600)
        self.plot_chart(vuln_data)

    def plot_chart(self, vuln_data):
        labels = list(vuln_data.keys())
        sizes = list(vuln_data.values())

        if not sizes:
            html = "<h2 style='text-align:center; color:gray;'>No Data Available</h2>"
            self.setHtml(html)
            return

        colors = ['#FF6F61', '#6B5B95', '#88B04B', '#F7CAC9', '#92A8D1',
                  '#955251', '#B565A7', '#009B77', '#DD4124', '#D65076']

        fig = go.Figure(
            data=[go.Pie(
                labels=labels,
                values=sizes,
                marker=dict(colors=colors[:len(labels)], line=dict(color='#FFFFFF', width=1)),
                hoverinfo='label+percent+value',
                textinfo='percent',
                textfont_size=14,
                textfont=dict(family='Arial', color='black')
            )]
        )

        fig.update_layout(
            title_font_size=20,
            showlegend=True,
            paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=50, b=20, l=20, r=20)
        )

        # Save plot to a temporary HTML file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f:
            fig.write_html(f.name)
            self.load(QUrl.fromLocalFile(os.path.abspath(f.name)))


class HistoryTab(QtWidgets.QWidget):
    def __init__(self, parent=None, tab_widget=None):
        super().__init__(parent)
        self.tabWidget = tab_widget
        self.setupUi()

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

        from controller.Tabs_Controller.history_tab_controller import HistoryTabController
        self.controller = HistoryTabController(self)
        self.controller.load_pie_chart_async()

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

    @staticmethod
    def load_stylesheet(file_path):
        try:
            with open(file_path, "r") as f:
                return f.read()
        except FileNotFoundError:
            print(f"Warning: Stylesheet '{file_path}' not found.")
            return ""

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

    stylesheet = HistoryTab.load_stylesheet("GUI/theme_switch/dark_style.qss")
    app.setStyleSheet(stylesheet)
    window = QtWidgets.QMainWindow()
    history_tab = HistoryTab()
    from controller.Tabs_Controller.history_tab_controller import HistoryTabController
    controller = HistoryTabController(history_tab)
    window.setCentralWidget(history_tab)
    window.setWindowTitle("Security Scanner")
    window.resize(1000, 600)
    window.show()
    sys.exit(app.exec())
