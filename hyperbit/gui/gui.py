# Copyright 2015 HyperBit developers

from PyQt5.QtCore import QSortFilterProxyModel, Qt
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5 import uic
import os.path
import sys

from hyperbit import wallet, helper
from hyperbit.gui import models, identicon

def resource_path(path):
    try:
        return os.path.join(sys._MEIPASS, path)
    except:
        return os.path.join(os.path.dirname(__file__), path)

class NetworkConfig(QDialog):
    def __init__(self, core, parent=None):
        super().__init__(parent)
        self._core = core
        uic.loadUi(resource_path('data/NetworkConfig.ui'), self)


class DeterministicIdentity(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path('data/DeterministicIdentity.ui'), self)


class JoinChannel(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path('data/JoinChannel.ui'), self)


class NewIdentityDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path('data/NewIdentity.ui'), self)


class MainWindow(QMainWindow):
    def __init__(self, core, peers, inv, wal, list, scanner):
        super().__init__()
        self._core = core
        self._peers = peers
        self._scanner = scanner
        self._inv = inv
        self._wal = wal
        self._list = list
        uic.loadUi(resource_path('data/MainWindow.ui'), self)
        peers.on_stats_changed.append(self.on_stats_changed)
        inv.on_stats_changed.append(self.on_stats_changed)
        self.on_stats_changed()
        model = models.ObjectModel(inv)
        proxyModel = QSortFilterProxyModel()
        proxyModel.setSourceModel(model)
        self.tableView.setModel(proxyModel)

        self._threadModel = models.ThreadModel(list)
        self.threads.setModel(self._threadModel)
        self.threads.selectionModel().selectionChanged.connect(self._on_threads_selectionChanged)
        self.messages_reply.clicked.connect(self._on_messages_reply_clicked)

        self._progressBar = QProgressBar()
        self._progressBar.setMinimum(0)
        self._progressBar.setTextVisible(True)
        self._progressBar.setFormat('Scanning (%v / %m)')
        self.statusBar.addPermanentWidget(self._progressBar, 0)
        self._progressBar.hide()
        scanner.on_change.append(self._updateProgress)

        self._channelModel = models.IdentityModel(wal)
        self.channels_list.setModel(self._channelModel)
        self.channels_join.clicked.connect(self._on_channel_join_clicked)
        self.channels_send.clicked.connect(self._on_channel_send_clicked)
        self.channels_list.selectionModel().selectionChanged.connect(self._channels_list_selectionChanged)
        self.channels_send.setEnabled(False)

        self._connectionModel = models.ConnectionModel(peers)
        self.status_connections.setModel(self._connectionModel)

        self.configureNetwork.clicked.connect(self._configure_network2)

    def configure_network(self):
        network_dialog = NetworkConfig(self._core, self)
        if self._core.get_config('network.proxy') == 'tor':
            network_dialog.raTor.setChecked(True)
        network_dialog.liListen.setText(str(self._core.get_config('network.listen_port', 8444)))
        network_dialog.liHost.setText(self._core.get_config('network.tor_host', '127.0.0.1'))
        network_dialog.liPort.setText(str(self._core.get_config('network.tor_port', 9050)))
        network_dialog.exec()
        if network_dialog.result():
            if network_dialog.raNone.isChecked():
                self._core.set_config('network.proxy', 'disabled')
            if network_dialog.raTor.isChecked():
                self._core.set_config('network.proxy', 'tor')
            self._core.set_config('network.listen_port', int(network_dialog.liListen.text()))
            self._core.set_config('network.tor_host', network_dialog.liHost.text())
            self._core.set_config('network.tor_port', int(network_dialog.liPort.text()))
            return True
        else:
            return False

    def _configure_network2(self):
        if self.configure_network():
            QMessageBox.warning(self, 'HyperBit', 'Changes will not be applied until restart of HyperBit')

    def _updateProgress(self):
        if self._scanner.max < 100:
            self._progressBar.hide()
        else:
            self._progressBar.setMaximum(self._scanner.max)
            self._progressBar.setValue(self._scanner.value)
            self._progressBar.show()

    def _on_threads_selectionChanged(self, selection):
        indexes = selection.indexes()
        if len(indexes) == 0:
            self.messages.setPlainText('')
        else:
            index = indexes[0]
            thread = self._threadModel.get_thread(index)
            self.messages.setPlainText('')
            cursor = self.messages.textCursor()
            format = QTextCharFormat()
            format.setFontWeight(QFont.Bold)
            format.setFontPointSize(14)
            cursor.setCharFormat(format)
            first = True
            cursor.insertText(thread.subject.strip())
            for comment in thread.comments:
                if not first:
                    charFormat = QTextCharFormat()
                    charFormat.setFontPointSize(2.0)
                    blockFormat = QTextBlockFormat()
                    blockFormat.setBackground(QColor(0x66, 0x99, 0x99))
                    cursor.insertBlock(blockFormat, charFormat)
                charFormat = QTextCharFormat()
                blockFormat = QTextBlockFormat()
                blockFormat.setTopMargin(3.0)
                blockFormat.setBottomMargin(3.0)
                cursor.insertBlock(blockFormat, charFormat)
                cursor.insertImage(identicon.get(comment.creator, 8).toImage())
                cursor.insertText(' ' + comment.text.strip())
                first = False
            thread.unread = 0

    def _on_channel_join_clicked(self):
        dialog = JoinChannel(self)
        dialog.exec()
        if dialog.result() == QDialog.Accepted:
            text = dialog.passphrase.text()
            self._wal.new_deterministic('[chan] '+text, text)

    def _channels_list_selectionChanged(self, selection):
        indexes = selection.indexes()
        if len(indexes) == 0:
            self.channels_send.setEnabled(False)
        else:
            self.channels_send.setEnabled(True)

    def _on_channel_send_clicked(self):
        if self.channels_message.toPlainText() == '':
            return
        index = self.channels_list.selectionModel().selection().indexes()[0]
        src = self._channelModel.get_identity(index)
        dst = src.profile
        subject = self.channels_subject.text()
        body = self.channels_message.toPlainText()
        message = helper.create_message(subject, body)
        helper.send_message(src, dst, 2, message, self._inv)
        self.channels_subject.setText('')
        self.channels_message.setPlainText('')

    def _on_messages_reply_clicked(self):
        if self.messages_message.toPlainText() == '':
            return
        index = self.threads.selectionModel().selection().indexes()[0]
        thread = self._threadModel.get_thread(index)
        src = self._wal.get_identity(thread.channel)
        dst = src.profile
        subject = thread.subject
        body = self.messages_message.toPlainText()
        parent = thread.longest
        message = helper.create_message(subject, body, parent)
        helper.send_message(src, dst, 2, message, self._inv)
        self.messages_message.setPlainText('')

    def on_stats_changed(self):
        self.objects.setText(str(self._inv.count()))
        self.peers.setText(str(self._peers.count_all()))
        self.connections.setText(str(self._peers.count_connected()))

