# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main1030.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
import rec_rc

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(696, 646)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setSpacing(0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.frame = QtWidgets.QFrame(self.centralwidget)
        self.frame.setMinimumSize(QtCore.QSize(0, 0))
        self.frame.setMaximumSize(QtCore.QSize(167777, 16777))
        self.frame.setStyleSheet("QFrame{\n"
"background-color: rgba(255, 255, 255, 242);\n"
"border:0px solid red;\n"
"border-radius:8px;\n"
" }")
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.frame)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setSpacing(0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setSpacing(0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.frame_3 = QtWidgets.QFrame(self.frame)
        self.frame_3.setMinimumSize(QtCore.QSize(0, 0))
        self.frame_3.setMaximumSize(QtCore.QSize(16777215, 16777))
        self.frame_3.setStyleSheet("background-color: rgba(255, 255, 255, 0);")
        self.frame_3.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_3.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_3.setObjectName("frame_3")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout(self.frame_3)
        self.horizontalLayout_5.setContentsMargins(8, 8, 8, 8)
        self.horizontalLayout_5.setSpacing(5)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setSpacing(0)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.widget = QtWidgets.QWidget(self.frame_3)
        self.widget.setMinimumSize(QtCore.QSize(48, 0))
        self.widget.setMaximumSize(QtCore.QSize(48, 33333))
        #self.widget.setStyleSheet("image: url(:/png/images/字母/M.png);")
        self.widget.setObjectName("widget")
        self.horizontalLayout_4.addWidget(self.widget)
        self.label_3 = QtWidgets.QLabel(self.frame_3)
        self.label_3.setMinimumSize(QtCore.QSize(0, 0))
        self.label_3.setMaximumSize(QtCore.QSize(16777215, 56))
        self.label_3.setStyleSheet("color: rgb(252, 12, 68);\n"
"padding-left:12px")
        self.label_3.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_4.addWidget(self.label_3)
        self.pushButton = QtWidgets.QPushButton(self.frame_3)
        self.pushButton.setMinimumSize(QtCore.QSize(48, 48))
        self.pushButton.setMaximumSize(QtCore.QSize(48, 48))
        self.pushButton.setStyleSheet("QPushButton{\n"
"    margin-right:3px;\n"
"    margin-bottom:0px;\n"
"    color: rgb(255, 255, 255);\n"
"    \n"
"    image: url(:/svg/images/svg/close-one.svg);\n"
"    border:1px outset rgb(255, 255, 255);\n"
"    border-radius:8px;\n"
"}\n"
"QPushButton:hover {\n"
"\n"
"border:2px outset rgba(36, 36, 36,0);\n"
"}\n"
"QPushButton:pressed {\n"
"\n"
"border:4px outset rgba(36, 36, 36,0);\n"
"}\n"
"")
        self.pushButton.setText("")
        self.pushButton.setIconSize(QtCore.QSize(32, 32))
        self.pushButton.setObjectName("pushButton")
        self.horizontalLayout_4.addWidget(self.pushButton)
        self.horizontalLayout_5.addLayout(self.horizontalLayout_4)
        self.verticalLayout.addWidget(self.frame_3)
        self.verticalLayout_3.addLayout(self.verticalLayout)
        self.verticalLayout_2.addWidget(self.frame)
        self.frame_2 = QtWidgets.QFrame(self.centralwidget)
        self.frame_2.setMaximumSize(QtCore.QSize(16777, 16777))
        self.frame_2.setStyleSheet("QFrame{\n"
"    background-color: rgb(255, 255, 255);\n"
"border-top-left-radius:20px;\n"
"border-top-right-radius:20px;\n"
"border-bottom-right-radius:20px;\n"
"border-bottom-left-radius:20px;\n"
"}")
        self.frame_2.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_2.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_2.setObjectName("frame_2")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.frame_2)
        self.verticalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_4.setSpacing(0)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.frame_4 = QtWidgets.QFrame(self.frame_2)
        self.frame_4.setMinimumSize(QtCore.QSize(0, 0))
        self.frame_4.setMaximumSize(QtCore.QSize(886, 698))
        self.frame_4.setStyleSheet("border:none")
        self.frame_4.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_4.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_4.setObjectName("frame_4")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.frame_4)
        self.verticalLayout_5.setSpacing(0)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setSpacing(0)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.label_23 = QtWidgets.QLabel(self.frame_4)
        self.label_23.setMinimumSize(QtCore.QSize(0, 49))
        font = QtGui.QFont()
        font.setPointSize(24)
        font.setBold(True)
        font.setWeight(75)
        self.label_23.setFont(font)
        self.label_23.setStyleSheet("border-radius: 10px;\n"
"border-bottom-left-radius: 0px;\n"
"color: rgb(255, 255, 255);\n"
"background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,stop:0 rgba(30, 30, 40,240), stop:1 rgba(255, 255, 255, 0));")
        self.label_23.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_23.setIndent(10)
        self.label_23.setObjectName("label_23")
        self.horizontalLayout_6.addWidget(self.label_23)
        self.pushButton_2 = QtWidgets.QPushButton(self.frame_4)
        self.pushButton_2.setMinimumSize(QtCore.QSize(24, 24))
        self.pushButton_2.setMaximumSize(QtCore.QSize(24, 24))
        self.pushButton_2.setStyleSheet("QPushButton{\n"
"    margin-right:3px;\n"
"    margin-bottom:0px;\n"
"    color: rgb(255, 255, 255);\n"
"    image: url(:/svg/images/svg/double-left.svg);\n"
"    border:1px outset rgb(255, 255, 255);\n"
"    border-radius:8px;\n"
"}\n"
"QPushButton:hover {\n"
"\n"
"border:2px outset rgba(36, 36, 36,0);\n"
"}\n"
"QPushButton:pressed {\n"
"\n"
"border:4px outset rgba(36, 36, 36,0);\n"
"}\n"
"")
        self.pushButton_2.setText("")
        self.pushButton_2.setIconSize(QtCore.QSize(32, 32))
        self.pushButton_2.setObjectName("pushButton_2")
        self.horizontalLayout_6.addWidget(self.pushButton_2)
        self.horizontalLayout_6.setStretch(0, 1)
        self.verticalLayout_5.addLayout(self.horizontalLayout_6)
        self.scrollArea_7 = QtWidgets.QScrollArea(self.frame_4)
        self.scrollArea_7.setStyleSheet("QScrollArea#scrollArea_7{\n"
"border-radius:0px;\n"
"border-top:1px outset rgb(153, 153, 153);\n"
"\n"
"}\n"
"")
        self.scrollArea_7.setWidgetResizable(True)
        self.scrollArea_7.setObjectName("scrollArea_7")
        self.scrollAreaWidgetContents_7 = QtWidgets.QWidget()
        self.scrollAreaWidgetContents_7.setGeometry(QtCore.QRect(0, 0, 668, 321))
        self.scrollAreaWidgetContents_7.setObjectName("scrollAreaWidgetContents_7")
        self.verticalLayout_21 = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents_7)
        self.verticalLayout_21.setObjectName("verticalLayout_21")
#         self.frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
#         self.frame_23.setMinimumSize(QtCore.QSize(0, 50))
#         self.frame_23.setStyleSheet("")
#         self.frame_23.setFrameShape(QtWidgets.QFrame.StyledPanel)
#         self.frame_23.setFrameShadow(QtWidgets.QFrame.Raised)
#         self.frame_23.setObjectName("frame_23")
#         self.horizontalLayout_28 = QtWidgets.QHBoxLayout(self.frame_23)
#         self.horizontalLayout_28.setContentsMargins(0, 0, 0, 0)
#         self.horizontalLayout_28.setSpacing(12)
#         self.horizontalLayout_28.setObjectName("horizontalLayout_28")
#         self.frame_24 = QtWidgets.QFrame(self.frame_23)
#         self.frame_24.setMinimumSize(QtCore.QSize(32, 32))
#         self.frame_24.setStyleSheet("image: url(:/png/img/svg/女孩1.png);")
#         self.frame_24.setFrameShape(QtWidgets.QFrame.NoFrame)
#         self.frame_24.setFrameShadow(QtWidgets.QFrame.Raised)
#         self.frame_24.setObjectName("frame_24")
#         self.horizontalLayout_28.addWidget(self.frame_24)
#         self.plainTextEdit = QtWidgets.QPlainTextEdit(self.frame_23)
#         self.plainTextEdit.setAcceptDrops(False)
#         self.plainTextEdit.setStyleSheet("text-align: right;\n"
# "border-radius: 20px;\n"
# "background-color: rgb(255, 255, 255);\n"
# "padding:10px;")
#         self.plainTextEdit.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
#         self.plainTextEdit.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
#         self.plainTextEdit.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustIgnored)
#         self.plainTextEdit.setTabChangesFocus(False)
#         self.plainTextEdit.setDocumentTitle("")
#         self.plainTextEdit.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
#         self.plainTextEdit.setReadOnly(True)
#         self.plainTextEdit.setOverwriteMode(False)
#         self.plainTextEdit.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
#         self.plainTextEdit.setBackgroundVisible(False)
#         self.plainTextEdit.setCenterOnScroll(False)
#         self.plainTextEdit.setObjectName("plainTextEdit")
#         self.horizontalLayout_28.addWidget(self.plainTextEdit)
#         self.horizontalLayout_28.setStretch(0, 1)
#         self.horizontalLayout_28.setStretch(1, 10)
#         self.verticalLayout_21.addWidget(self.frame_23)
#         self.frame_25 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
#         self.frame_25.setMinimumSize(QtCore.QSize(0, 50))
#         self.frame_25.setFrameShape(QtWidgets.QFrame.StyledPanel)
#         self.frame_25.setFrameShadow(QtWidgets.QFrame.Raised)
#         self.frame_25.setObjectName("frame_25")
#         self.horizontalLayout_29 = QtWidgets.QHBoxLayout(self.frame_25)
#         self.horizontalLayout_29.setContentsMargins(0, 0, 0, 0)
#         self.horizontalLayout_29.setSpacing(12)
#         self.horizontalLayout_29.setObjectName("horizontalLayout_29")
#         self.frame_26 = QtWidgets.QFrame(self.frame_25)
#         self.frame_26.setMinimumSize(QtCore.QSize(32, 0))
#         self.frame_26.setStyleSheet("image: url(:/png/img/svg/女孩1.png);")
#         self.frame_26.setFrameShape(QtWidgets.QFrame.NoFrame)
#         self.frame_26.setFrameShadow(QtWidgets.QFrame.Raised)
#         self.frame_26.setObjectName("frame_26")
#         self.horizontalLayout_29.addWidget(self.frame_26)
#         self.plainTextEdit_2 = QtWidgets.QPlainTextEdit(self.frame_25)
#         self.plainTextEdit_2.setAcceptDrops(False)
#         self.plainTextEdit_2.setStyleSheet("text-align: right;\n"
# "border-radius: 20px;\n"
# "background-color: rgb(255, 255, 255);\n"
# "padding:10px;")
#         self.plainTextEdit_2.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
#         self.plainTextEdit_2.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
#         self.plainTextEdit_2.setTabChangesFocus(False)
#         self.plainTextEdit_2.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
#         self.plainTextEdit_2.setReadOnly(True)
#         self.plainTextEdit_2.setObjectName("plainTextEdit_2")
#         self.horizontalLayout_29.addWidget(self.plainTextEdit_2)
#         self.horizontalLayout_29.setStretch(0, 1)
#         self.horizontalLayout_29.setStretch(1, 10)
#         self.verticalLayout_21.addWidget(self.frame_25)
#         self.frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
#         self.frame_27.setMinimumSize(QtCore.QSize(0, 50))
#         self.frame_27.setFrameShape(QtWidgets.QFrame.StyledPanel)
#         self.frame_27.setFrameShadow(QtWidgets.QFrame.Raised)
#         self.frame_27.setObjectName("frame_27")
#         self.horizontalLayout_30 = QtWidgets.QHBoxLayout(self.frame_27)
#         self.horizontalLayout_30.setContentsMargins(0, 0, 0, 0)
#         self.horizontalLayout_30.setSpacing(12)
#         self.horizontalLayout_30.setObjectName("horizontalLayout_30")
#         self.plainTextEdit_3 = QtWidgets.QPlainTextEdit(self.frame_27)
#         self.plainTextEdit_3.setAcceptDrops(False)
#         self.plainTextEdit_3.setLayoutDirection(QtCore.Qt.LeftToRight)
#         self.plainTextEdit_3.setStyleSheet("text-align: right;\n"
# "border-radius: 20px;\n"
# "background-color: rgb(255, 255, 255);\n"
# "padding:10px;")
#         self.plainTextEdit_3.setFrameShape(QtWidgets.QFrame.NoFrame)
#         self.plainTextEdit_3.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
#         self.plainTextEdit_3.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
#         self.plainTextEdit_3.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
#         self.plainTextEdit_3.setReadOnly(True)
#         self.plainTextEdit_3.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
#         self.plainTextEdit_3.setObjectName("plainTextEdit_3")
#         self.horizontalLayout_30.addWidget(self.plainTextEdit_3)
#         self.frame_28 = QtWidgets.QFrame(self.frame_27)
#         self.frame_28.setMinimumSize(QtCore.QSize(32, 0))
#         self.frame_28.setStyleSheet("image: url(:/png/img/svg/男孩3.png);")
#         self.frame_28.setFrameShape(QtWidgets.QFrame.NoFrame)
#         self.frame_28.setFrameShadow(QtWidgets.QFrame.Raised)
#         self.frame_28.setObjectName("frame_28")
#         self.horizontalLayout_30.addWidget(self.frame_28)
#         self.horizontalLayout_30.setStretch(0, 10)
#         self.horizontalLayout_30.setStretch(1, 1)
#         self.verticalLayout_21.addWidget(self.frame_27)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_21.addItem(spacerItem)
        self.verticalLayout_21.setStretch(0, 1)
        self.verticalLayout_21.setStretch(1, 1)
        self.verticalLayout_21.setStretch(2, 1)
        self.verticalLayout_21.setStretch(3, 10)
        self.scrollArea_7.setWidget(self.scrollAreaWidgetContents_7)
        self.verticalLayout_5.addWidget(self.scrollArea_7)
        self.frame_29 = QtWidgets.QFrame(self.frame_4)
        self.frame_29.setMaximumSize(QtCore.QSize(16777215, 32))
        self.frame_29.setStyleSheet("QFrame#frame_29{\n"
"border-top:1px outset rgb(153, 153, 153);\n"
"border-radius:0px;\n"
"}\n"
"                                                                ")
        self.frame_29.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_29.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_29.setObjectName("frame_29")
        self.horizontalLayout_31 = QtWidgets.QHBoxLayout(self.frame_29)
        self.horizontalLayout_31.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_31.setSpacing(12)
        self.horizontalLayout_31.setObjectName("horizontalLayout_31")
        self.pushButton_5 = QtWidgets.QPushButton(self.frame_29)
        self.pushButton_5.setStyleSheet("QPushButton{\n"
"    image: url(:/svg/images/svg/smiling-face.svg);\n"
"}\n"
"QPushButton:hover {\n"
" border:1px outset rgba(36, 36, 36,0);\n"
"}\n"
"QPushButton:pressed {\n"
"border:2px outset rgba(36, 36, 36,0);\n"
"}\n"
"                                                                            ")
        self.pushButton_5.setText("")
        self.pushButton_5.setObjectName("pushButton_5")
        self.horizontalLayout_31.addWidget(self.pushButton_5)
        self.pushButton_6 = QtWidgets.QPushButton(self.frame_29)
        self.pushButton_6.setStyleSheet("QPushButton{\n"
"    image: url(:/svg/images/svg/scissors.svg);\n"
"}\n"
"QPushButton:hover {\n"
" border:1px outset rgba(36, 36, 36,0);\n"
"}\n"
"QPushButton:pressed {\n"
"border:2px outset rgba(36, 36, 36,0);\n"
"}\n"
"                                                                            ")
        self.pushButton_6.setText("")
        self.pushButton_6.setObjectName("pushButton_6")
        self.horizontalLayout_31.addWidget(self.pushButton_6)
        self.pushButton_7 = QtWidgets.QPushButton(self.frame_29)
        self.pushButton_7.setStyleSheet("QPushButton{\n"
"    image: url(:/svg/images/svg/picture.svg);\n"
"}\n"
"QPushButton:hover {\n"
" border:1px outset rgba(36, 36, 36,0);\n"
"}\n"
"QPushButton:pressed {\n"
"border:2px outset rgba(36, 36, 36,0);\n"
"}\n"
"                                                                            ")
        self.pushButton_7.setText("")
        self.pushButton_7.setObjectName("pushButton_7")
        self.horizontalLayout_31.addWidget(self.pushButton_7)
        self.pushButton_8 = QtWidgets.QPushButton(self.frame_29)
        self.pushButton_8.setStyleSheet("QPushButton{\n"
"    image: url(:/svg/images/svg/history-query.svg);\n"
"}\n"
"QPushButton:hover {\n"
" border:1px outset rgba(36, 36, 36,0);\n"
"}\n"
"QPushButton:pressed {\n"
"border:2px outset rgba(36, 36, 36,0);\n"
"}\n"
"                                                                            ")
        self.pushButton_8.setText("")
        self.pushButton_8.setObjectName("pushButton_8")
        self.horizontalLayout_31.addWidget(self.pushButton_8)
        
        self.comboBox = QtWidgets.QComboBox(self.frame_29)
        self.comboBox.addItem("KYBER512")
        self.comboBox.addItem("KYBER768")
        self.comboBox.addItem("KYBER1024")
        self.comboBox.addItem("KYBER512_Mismatch")
        self.comboBox.addItem("KYBER512_Recovery")
        self.comboBox.addItem("KYBER512_Backdoor")
        self.comboBox.addItem("KYBER768_Mismatch")
        self.comboBox.addItem("KYBER768_Recovery")
        self.comboBox.addItem("KYBER768_Backdoor")
        self.comboBox.addItem("KYBER1024_Mismatch")
        self.comboBox.addItem("KYBER1024_Recovery")
        self.comboBox.addItem("KYBER1024_Backdoor")
        self.comboBox.setCurrentIndex(0)
        self.comboBox.setObjectName("comboBox")
        self.comboBox.setFixedWidth(200)
        self.comboBox.setStyleSheet("font-size: 12px; font-family: Arial;Fusion;")

        self.horizontalLayout_31.addWidget(self.comboBox)
        
        self.frame_30 = QtWidgets.QFrame(self.frame_29)
        self.frame_30.setMaximumSize(QtCore.QSize(16777215, 32))
        self.frame_30.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_30.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_30.setObjectName("frame_30")
        self.horizontalLayout_32 = QtWidgets.QHBoxLayout(self.frame_30)
        self.horizontalLayout_32.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_32.setSpacing(12)
        self.horizontalLayout_32.setObjectName("horizontalLayout_32")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_32.addItem(spacerItem1)
        self.horizontalLayout_31.addWidget(self.frame_30)
        self.verticalLayout_5.addWidget(self.frame_29)
        self.textEdit_2 = QtWidgets.QTextEdit(self.frame_4)
        self.textEdit_2.setStyleSheet("color: rgba(0, 0, 0, 200);\n"
"border-radius: 10px;\n"
"background-color: qlineargradient(x1:0, y1:1, x1:1, y1:2,stop:0 rgba(174, 99, 255,10), stop:1 rgba(255, 255, 255, 0));")
        self.textEdit_2.setObjectName("textEdit_2")
        self.verticalLayout_5.addWidget(self.textEdit_2)
        self.horizontalLayout.addWidget(self.frame_4)
        self.widget_3 = QtWidgets.QWidget(self.frame_2)
        self.widget_3.setMinimumSize(QtCore.QSize(0, 0))
        self.widget_3.setMaximumSize(QtCore.QSize(0, 16777215))
        self.widget_3.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.widget_3.setStyleSheet("background-color: rgba(255, 255, 255, 0);\n"
"                                                    ")
        self.widget_3.setObjectName("widget_3")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.widget_3)
        self.verticalLayout_6.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_6.setSpacing(0)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.listWidget = QtWidgets.QListWidget(self.widget_3)
        self.listWidget.setMaximumSize(QtCore.QSize(200, 16777215))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.listWidget.setFont(font)
        self.listWidget.setStyleSheet("QListView {\n"
"    border: 15px solid white; /* 设置边框的大小，样式，颜色 */\n"
"    border-radius: 10px;\n"
"}\n"
"QListView::item{\n"
"background-color: transparent;\n"
"    padding: 5px;\n"
"}\n"
"QListView::item:hover {\n"
"    background-color: rgba(165, 205, 255,220);\n"
"\n"
"    border-bottom: 1px solid rgba(165, 205, 255,220);\n"
"}\n"
"QListView::item:selected {\n"
"    background-color: transparent;\n"
"\n"
"    color: rgb(0, 0, 0);\n"
"    border-bottom: 2px solid rgba(165, 205, 255,255);\n"
"}\n"
"\n"
"\n"
"\n"
"QProgressBar::chunk {\n"
"        border-radius:5px;\n"
"}")
        self.listWidget.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.listWidget.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.listWidget.setIconSize(QtCore.QSize(32, 32))
        self.listWidget.setObjectName("listWidget")
        # item = QtWidgets.QListWidgetItem()
        # icon = QtGui.QIcon()
        # icon.addPixmap(QtGui.QPixmap(":/png/img/svg/篮球.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        # item.setIcon(icon)
        # self.listWidget.addItem(item)
        # item = QtWidgets.QListWidgetItem()
        # icon1 = QtGui.QIcon()
        # icon1.addPixmap(QtGui.QPixmap(":/png/img/svg/男孩1.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        # item.setIcon(icon1)
        # self.listWidget.addItem(item)
        # item = QtWidgets.QListWidgetItem()
        # icon2 = QtGui.QIcon()
        # icon2.addPixmap(QtGui.QPixmap(":/png/img/svg/男孩2.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        # item.setIcon(icon2)
        # self.listWidget.addItem(item)
        # item = QtWidgets.QListWidgetItem()
        # icon3 = QtGui.QIcon()
        # icon3.addPixmap(QtGui.QPixmap(":/png/img/svg/男孩3.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        # item.setIcon(icon3)
        # self.listWidget.addItem(item)
        # item = QtWidgets.QListWidgetItem()
        # icon4 = QtGui.QIcon()
        # icon4.addPixmap(QtGui.QPixmap(":/png/img/svg/男孩4.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        # item.setIcon(icon4)
        # self.listWidget.addItem(item)
        # item = QtWidgets.QListWidgetItem()
        # icon5 = QtGui.QIcon()
        # icon5.addPixmap(QtGui.QPixmap(":/png/img/svg/女孩1.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        # item.setIcon(icon5)
        # self.listWidget.addItem(item)
        # item = QtWidgets.QListWidgetItem()
        # icon6 = QtGui.QIcon()
        # icon6.addPixmap(QtGui.QPixmap(":/png/img/svg/博士帽.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        # item.setIcon(icon6)
        # self.listWidget.addItem(item)
        # item = QtWidgets.QListWidgetItem()
        # icon7 = QtGui.QIcon()
        # icon7.addPixmap(QtGui.QPixmap(":/buttom/img/buttom/张嘴哭_loudly-crying-face-whit-open-mouth.svg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        # item.setIcon(icon7)
        # self.listWidget.addItem(item)
        # item = QtWidgets.QListWidgetItem()
        # icon8 = QtGui.QIcon()
        # icon8.addPixmap(QtGui.QPixmap(":/png/img/svg/女孩z.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        # item.setIcon(icon8)
        # self.listWidget.addItem(item)
        self.verticalLayout_6.addWidget(self.listWidget)
        self.horizontalLayout.addWidget(self.widget_3)
        self.verticalLayout_4.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setSpacing(0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.widget_2 = QtWidgets.QWidget(self.frame_2)
        self.widget_2.setMinimumSize(QtCore.QSize(0, 24))
        self.widget_2.setMaximumSize(QtCore.QSize(16777215, 24))
        self.widget_2.setCursor(QtGui.QCursor(QtCore.Qt.SizeVerCursor))
        self.widget_2.setStyleSheet("background-color: rgba(255, 255, 255, 0);")
        self.widget_2.setObjectName("widget_2")
        self.horizontalLayout_2.addWidget(self.widget_2)
        self.widget_4 = QtWidgets.QWidget(self.frame_2)
        self.widget_4.setMinimumSize(QtCore.QSize(24, 24))
        self.widget_4.setMaximumSize(QtCore.QSize(24, 24))
        self.widget_4.setCursor(QtGui.QCursor(QtCore.Qt.SizeFDiagCursor))
        self.widget_4.setStyleSheet("background-color: rgba(255, 255, 255, 0);")
        self.widget_4.setObjectName("widget_4")
        self.horizontalLayout_2.addWidget(self.widget_4)
        self.horizontalLayout_2.setStretch(0, 1)
        self.verticalLayout_4.addLayout(self.horizontalLayout_2)
        self.verticalLayout_4.setStretch(0, 1)
        self.verticalLayout_2.addWidget(self.frame_2)
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        self.textEdit_2.setFocus()
        self.textEdit_2.textChanged.connect(self.text_changed)
        self.listWidget.itemClicked['QListWidgetItem*'].connect(self.change)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        # self.label_3.setText(_translate("MainWindow", "未读消息24条"))
        # self.label_23.setText(_translate("MainWindow", "IKUN"))
        # self.plainTextEdit.setPlainText(_translate("MainWindow", "There will be no regret and sorrow if you fight with all your strength."))
        # self.plainTextEdit_2.setPlainText(_translate("MainWindow", "Time is a bird for ever on the wing."))
        # self.plainTextEdit_3.setPlainText(_translate("MainWindow", "Today, give a stranger one of your smiles. It might be the only sunshine he sees all day."))
        self.textEdit_2.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'.AppleSystemUIFont\'; font-size:13pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"></p></body></html>"))
        __sortingEnabled = self.listWidget.isSortingEnabled()
        self.listWidget.setSortingEnabled(False)
        # item = self.listWidget.item(0)
        # item.setText(_translate("MainWindow", "蔡徐坤"))
        # item = self.listWidget.item(1)
        # item.setText(_translate("MainWindow", "丁真"))
        # item = self.listWidget.item(2)
        # item.setText(_translate("MainWindow", "刘畊宏"))
        # item = self.listWidget.item(3)
        # item.setText(_translate("MainWindow", "潘周聃"))
        # item = self.listWidget.item(4)
        # item.setText(_translate("MainWindow", "龙友林"))
        # item = self.listWidget.item(5)
        # item.setText(_translate("MainWindow", "王冰冰"))
        # item = self.listWidget.item(6)
        # item.setText(_translate("MainWindow", "董宇辉"))
        # item = self.listWidget.item(7)
        # item.setText(_translate("MainWindow", "反诈警官老陈"))
        # item = self.listWidget.item(8)
        # item.setText(_translate("MainWindow", "王心凌"))
        self.listWidget.setSortingEnabled(__sortingEnabled)
