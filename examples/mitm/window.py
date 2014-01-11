# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'window.ui'
#
# Created: Sat Mar 16 14:21:30 2013
#      by: PyQt4 UI code generator 4.9.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

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
        self.horizontalLayout_4 = QtGui.QHBoxLayout()
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.connectionlist = QtGui.QListWidget(Dialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.connectionlist.sizePolicy().hasHeightForWidth())
        self.connectionlist.setSizePolicy(sizePolicy)
        self.connectionlist.setMinimumSize(QtCore.QSize(0, 125))
        self.connectionlist.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.connectionlist.setObjectName(_fromUtf8("connectionlist"))
        self.horizontalLayout_4.addWidget(self.connectionlist)
        self.verticalLayout_4 = QtGui.QVBoxLayout()
        self.verticalLayout_4.setObjectName(_fromUtf8("verticalLayout_4"))
        self.listenbutton = QtGui.QPushButton(Dialog)
        self.listenbutton.setObjectName(_fromUtf8("listenbutton"))
        self.verticalLayout_4.addWidget(self.listenbutton)
        self.horizontalLayout_4.addLayout(self.verticalLayout_4)
        self.regular_chat_layout.addLayout(self.horizontalLayout_4)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.verticalLayout_2 = QtGui.QVBoxLayout()
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.labelsent = QtGui.QLabel(Dialog)
        self.labelsent.setAlignment(QtCore.Qt.AlignCenter)
        self.labelsent.setObjectName(_fromUtf8("labelsent"))
        self.verticalLayout_2.addWidget(self.labelsent)
        self.textsent = QtGui.QTextEdit(Dialog)
        self.textsent.setObjectName(_fromUtf8("textsent"))
        self.verticalLayout_2.addWidget(self.textsent)
        self.horizontalLayout_2.addLayout(self.verticalLayout_2)
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.labelreceived = QtGui.QLabel(Dialog)
        self.labelreceived.setAlignment(QtCore.Qt.AlignCenter)
        self.labelreceived.setObjectName(_fromUtf8("labelreceived"))
        self.verticalLayout.addWidget(self.labelreceived)
        self.textreceived = QtGui.QTextEdit(Dialog)
        self.textreceived.setObjectName(_fromUtf8("textreceived"))
        self.verticalLayout.addWidget(self.textreceived)
        self.horizontalLayout_2.addLayout(self.verticalLayout)
        self.regular_chat_layout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.inputtext = QtGui.QPlainTextEdit(Dialog)
        self.inputtext.setEnabled(False)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.inputtext.sizePolicy().hasHeightForWidth())
        self.inputtext.setSizePolicy(sizePolicy)
        self.inputtext.setMinimumSize(QtCore.QSize(0, 125))
        self.inputtext.setObjectName(_fromUtf8("inputtext"))
        self.horizontalLayout_3.addWidget(self.inputtext)
        self.inputbutton = QtGui.QPushButton(Dialog)
        self.inputbutton.setEnabled(False)
        self.inputbutton.setObjectName(_fromUtf8("inputbutton"))
        self.horizontalLayout_3.addWidget(self.inputbutton)
        self.regular_chat_layout.addLayout(self.horizontalLayout_3)
        self.horizontalLayout.addLayout(self.regular_chat_layout)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "Dialog", None, QtGui.QApplication.UnicodeUTF8))
        self.listenbutton.setText(QtGui.QApplication.translate("Dialog", "Hook", None, QtGui.QApplication.UnicodeUTF8))
        self.labelsent.setText(QtGui.QApplication.translate("Dialog", "Sent", None, QtGui.QApplication.UnicodeUTF8))
        self.labelreceived.setText(QtGui.QApplication.translate("Dialog", "Received", None, QtGui.QApplication.UnicodeUTF8))
        self.inputbutton.setText(QtGui.QApplication.translate("Dialog", "Send", None, QtGui.QApplication.UnicodeUTF8))

