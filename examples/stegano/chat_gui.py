# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'chat.ui'
#
# Created: Wed Nov 28 21:08:02 2012
#      by: PyQt4 UI code generator 4.9.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui
from PyQt4.QtGui import QDialog, QApplication

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(756, 504)
        self.horizontalLayout = QtGui.QHBoxLayout(Dialog)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.regular_chat_layout = QtGui.QVBoxLayout()
        self.regular_chat_layout.setObjectName(_fromUtf8("regular_chat_layout"))
        self.title_regular = QtGui.QLabel(Dialog)
        self.title_regular.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.title_regular.setObjectName(_fromUtf8("title_regular"))
        self.regular_chat_layout.addWidget(self.title_regular)
        self.view_regular = QtGui.QListWidget(Dialog)
        self.view_regular.setMinimumSize(QtCore.QSize(0, 300))
        self.view_regular.setObjectName(_fromUtf8("view_regular"))
        self.regular_chat_layout.addWidget(self.view_regular)
        self.line = QtGui.QFrame(Dialog)
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)
        self.line.setObjectName(_fromUtf8("line"))
        self.regular_chat_layout.addWidget(self.line)
        self.process_regular = QtGui.QLabel(Dialog)
        self.process_regular.setText(_fromUtf8(""))
        self.process_regular.setObjectName(_fromUtf8("process_regular"))
        self.regular_chat_layout.addWidget(self.process_regular)
        self.textedit_regular = QtGui.QPlainTextEdit(Dialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.textedit_regular.sizePolicy().hasHeightForWidth())
        self.textedit_regular.setSizePolicy(sizePolicy)
        self.textedit_regular.setMinimumSize(QtCore.QSize(0, 50))
        self.textedit_regular.setObjectName(_fromUtf8("textedit_regular"))
        self.regular_chat_layout.addWidget(self.textedit_regular)
        self.send_regular = QtGui.QPushButton(Dialog)
        self.send_regular.setMaximumSize(QtCore.QSize(332, 16777215))
        self.send_regular.setObjectName(_fromUtf8("send_regular"))
        self.regular_chat_layout.addWidget(self.send_regular)
        self.horizontalLayout.addLayout(self.regular_chat_layout)
        self.hidden_chat_layout = QtGui.QVBoxLayout()
        self.hidden_chat_layout.setObjectName(_fromUtf8("hidden_chat_layout"))
        self.title_hidden = QtGui.QLabel(Dialog)
        self.title_hidden.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.title_hidden.setObjectName(_fromUtf8("title_hidden"))
        self.hidden_chat_layout.addWidget(self.title_hidden)
        self.view_hidden = QtGui.QListWidget(Dialog)
        self.view_hidden.setMinimumSize(QtCore.QSize(0, 300))
        self.view_hidden.setObjectName(_fromUtf8("view_hidden"))
        self.hidden_chat_layout.addWidget(self.view_hidden)
        self.line_2 = QtGui.QFrame(Dialog)
        self.line_2.setFrameShape(QtGui.QFrame.HLine)
        self.line_2.setFrameShadow(QtGui.QFrame.Sunken)
        self.line_2.setObjectName(_fromUtf8("line_2"))
        self.hidden_chat_layout.addWidget(self.line_2)
        self.process_hidden = QtGui.QLabel(Dialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.process_hidden.sizePolicy().hasHeightForWidth())
        self.process_hidden.setSizePolicy(sizePolicy)
        self.process_hidden.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.process_hidden.setText(_fromUtf8(""))
        self.process_hidden.setObjectName(_fromUtf8("process_hidden"))
        self.hidden_chat_layout.addWidget(self.process_hidden)
        self.textedit_hidden = QtGui.QPlainTextEdit(Dialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.textedit_hidden.sizePolicy().hasHeightForWidth())
        self.textedit_hidden.setSizePolicy(sizePolicy)
        self.textedit_hidden.setMinimumSize(QtCore.QSize(0, 50))
        self.textedit_hidden.setObjectName(_fromUtf8("textedit_hidden"))
        self.hidden_chat_layout.addWidget(self.textedit_hidden)
        self.send_hidden = QtGui.QPushButton(Dialog)
        self.send_hidden.setObjectName(_fromUtf8("send_hidden"))
        self.hidden_chat_layout.addWidget(self.send_hidden)
        self.horizontalLayout.addLayout(self.hidden_chat_layout)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "Dialog", None, QtGui.QApplication.UnicodeUTF8))
        self.title_regular.setText(QtGui.QApplication.translate("Dialog", "Chat", None, QtGui.QApplication.UnicodeUTF8))
        self.send_regular.setText(QtGui.QApplication.translate("Dialog", "Send text", None, QtGui.QApplication.UnicodeUTF8))
        self.title_hidden.setText(QtGui.QApplication.translate("Dialog", "Hidden Chat", None, QtGui.QApplication.UnicodeUTF8))
        self.send_hidden.setText(QtGui.QApplication.translate("Dialog", "Send covert text", None, QtGui.QApplication.UnicodeUTF8))

if __name__ == "__main__":
    
    import sys
    app = QApplication(sys.argv)
    app.setApplicationName("SteganoChat")
    
    win = Ui_Dialog()
    win.show()
    app.exec_()
