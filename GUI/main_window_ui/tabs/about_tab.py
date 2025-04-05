from PyQt6 import QtCore, QtGui, QtWidgets

class AboutTab(QtWidgets.QWidget):
    def __init__(self, parent=None, tab_widget=None):
        super().__init__(parent)
        self.tabWidget = tab_widget
        self.setupUi()

    def setupUi(self):
        # Scroll Area
        self.about_tab_scrollArea = QtWidgets.QScrollArea(self)
        self.about_tab_scrollArea.setGeometry(QtCore.QRect(0, 10, 1191, 751))
        self.about_tab_scrollArea.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Preferred))
        self.about_tab_scrollArea.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.about_tab_scrollArea.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.about_tab_scrollArea.setWidgetResizable(True)
        self.about_tab_scrollArea.setObjectName("about_tab_scrollArea")

        # Scroll Area Contents
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 1189, 749))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")

        self.verticalLayout_9 = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)

        # Frame inside scroll area
        self.about_tab_scrollArea_2 = QtWidgets.QFrame()
        self.about_tab_scrollArea_2.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding))
        self.about_tab_scrollArea_2.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.about_tab_scrollArea_2.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.about_tab_scrollArea_2.setObjectName("about_tab_scrollArea_2")

        self.verticalLayout_10 = QtWidgets.QVBoxLayout(self.about_tab_scrollArea_2)

        # About App Label
        self.about_app_label = QtWidgets.QLabel("About this Application")
        self.about_app_label.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding))
        self.about_app_label.setObjectName("about_app_label")
        self.verticalLayout_10.addWidget(self.about_app_label)

        self.verticalLayout_9.addWidget(self.about_tab_scrollArea_2)
        self.about_tab_scrollArea.setWidget(self.scrollAreaWidgetContents)