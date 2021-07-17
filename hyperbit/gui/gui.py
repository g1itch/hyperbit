# Copyright 2015-2016 HyperBit developers

from PyQt5.QtCore import QSortFilterProxyModel, Qt
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5 import uic
import os.path
import sys

import pkg_resources

from hyperbit import base58, objtypes, wallet
from hyperbit.gui import models, identicon, parser


def resource_path(path):
    try:
        return os.path.join(sys._MEIPASS, path)
    except AttributeError:
        return pkg_resources.resource_filename(__name__, path)
        # return os.path.join(os.path.dirname(__file__), path)


class NetworkConfigDialog(QDialog):
    def __init__(self, core, parent=None):
        super().__init__(parent)
        self._core = core
        uic.loadUi(resource_path('data/NetworkConfigDialog.ui'), self)


class DeterministicIdentity(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path('data/DeterministicIdentityDialog.ui'), self)


class JoinChannel(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path('data/JoinChannelDialog.ui'), self)


class NewUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path('data/NewUserDialog.ui'), self)


class ChannelsTab(QSplitter):
    def __init__(self, core, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path('data/ChannelsTab.ui'), self)
        self._core = core

        self._channelModel = models.IdentityModel(self._core.wal)
        self.channels_list.setModel(self._channelModel)
        self.channels_join.clicked.connect(self._on_channel_join_clicked)
        self.channels_list.contextMenuEvent = self.show_context_menu
        self.comboFrom.setModel(self._channelModel)
        self.comboTo.setModel(self._channelModel)
        self.channels_send.clicked.connect(self._on_channel_send_clicked)
        self.buttonNewUser.clicked.connect(self._create_new_user)

    def _on_channel_join_clicked(self):
        dialog = JoinChannel(self)
        dialog.exec()
        if dialog.result() == QDialog.Accepted:
            text = dialog.passphrase.text()
            self._core.wal.new_deterministic('[chan] '+text, wallet.IdentityType.channel, text)

    def _on_channel_send_clicked(self):
        if self.comboFrom.currentIndex() < 0:
            return
        if self.comboTo.currentIndex() < 0:
            return
        if self.channels_subject.text().strip() == '':
            return
        if self.channels_message.toPlainText().strip() == '':
            return
        index = self.comboFrom.currentIndex()
        src = self._channelModel.get_identity_by_row(index)
        index2 = self.comboTo.currentIndex()
        dst = self._channelModel.get_identity_by_row(index2).profile
        subject = self.channels_subject.text()
        body = self.channels_message.toPlainText()
        message = objtypes.SimpleMessage(subject, body)
        self._core.send_message(src, dst, message)
        self.channels_subject.setText('')
        self.channels_message.setPlainText('')

    def show_context_menu(self, event):
        row = self.channels_list.indexAt(event.pos()).row()
        identity = self._channelModel.get_identity_by_row(row)
        address = identity.profile.address
        if row < 0:
            return
        menu = QMenu()
        def copy_address():
            qApp.clipboard().setText(address.to_str())
        menu.addAction('Copy address to clipboard').triggered.connect(copy_address)
        def delete():
            if QMessageBox.question(self, 'HyperBit', 'Are you sure you want to delete {}?'
                                   .format(self._core.wal.names.get(address.ripe))) == QMessageBox.Yes:
                self._core.wal.remove_identity(identity)
        menu.addAction('Delete').triggered.connect(delete)
        menu.exec(self.mapToGlobal(event.pos()))

    def _create_new_user(self):
        dialog = NewUserDialog(self)
        dialog.exec()
        if dialog.result():
            if dialog.random.isChecked():
                name = dialog.name.text()
                self._core.wal.new_random(name, wallet.IdentityType.normal)
            elif dialog.wif.isChecked():
                name = dialog.name.text()
                sigkey = base58.decode_wif(dialog.sigkey.text())
                deckey = base58.decode_wif(dialog.deckey.text())
                self._core.wal.new_identity(name, wallet.IdentityType.normal, sigkey, deckey)


class MessagesTab(QSplitter):
    def __init__(self, core, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path('data/MessagesTab.ui'), self)
        self._core = core

        self._threadModel = models.ThreadModel(self._core.list)
        self.threads.setModel(self._threadModel)
        self.threads.selectionModel().selectionChanged.connect(self._on_threads_selectionChanged)
        self.threads.contextMenuEvent = self._on_threads_context_menu_event

        self._channelModel = models.IdentityModel(self._core.wal)
        self.comboFrom2.setModel(self._channelModel)

        self.messages_reply.clicked.connect(self._on_messages_reply_clicked)

        self.cleaner = parser.MessageCleaner()

    def _on_threads_context_menu_event(self, event):
        row = self.threads.indexAt(event.pos()).row()
        if row < 0:
            return
        thread = self._threadModel.get_thread_by_row(row)
        menu = QMenu()
        def delete():
            self._core.list.remove_thread(thread)
        menu.addAction('Delete').triggered.connect(delete)
        menu.exec(self.mapToGlobal(event.pos()))

    def _on_threads_selectionChanged(self, selection):
        indexes = selection.indexes()
        if len(indexes) == 0:
            self.messages.setPlainText('')
        else:
            index = indexes[0]
            thread = self._threadModel.get_thread(index)
            for i in range(self._channelModel.rowCount()):
                identity = self._channelModel.get_identity_by_row(i)
                if identity.profile.address.to_bytes() == thread.channel:
                    self.comboFrom2.setCurrentIndex(i)
                    break
            self.messages.setPlainText('')
            cursor = self.messages.textCursor()
            format = QTextCharFormat()
            format.setFontWeight(QFont.Bold)
            format.setFontPointSize(14)
            cursor.setCharFormat(format)

            cursor.insertText(thread.subject.strip())
            for comment in thread.comments:
                charFormat = QTextCharFormat()
                blockFormat = QTextBlockFormat()
                blockFormat.setTopMargin(3.0)
                blockFormat.setBottomMargin(3.0)
                blockFormat.setBackground(QColor(0xdd, 0xdd, 0xdd))
                cursor.insertBlock(blockFormat, charFormat)
                cursor.insertImage(identicon.get(comment.creator, 8).toImage())
                cursor.setCharFormat(charFormat)
                if comment.creator:
                    address = wallet.Address.from_bytes(comment.creator)
                    cursor.insertText(' '+self._core.wal.names.get(address.ripe))
                else:
                    cursor.insertText(' <unknown>')
                blockFormat = QTextBlockFormat()
                blockFormat.setTopMargin(3.0)
                blockFormat.setBottomMargin(3.0)
                cursor.insertBlock(blockFormat, charFormat)
                text = comment.text.strip()

                clean = self.cleaner.clean_html(text)

                (cursor.insertHtml if self.cleaner.html
                    else cursor.insertText)(clean)

            thread.unread = 0

    def _on_messages_reply_clicked(self):
        if self.comboFrom2.currentIndex() < 0:
            return
        if self.messages_message.toPlainText().strip() == '':
            return
        index = self.threads.selectionModel().selection().indexes()[0]
        thread = self._threadModel.get_thread(index)
        dst = self._core.wal.get_identity(thread.channel).profile
        index2 = self.comboFrom2.currentIndex()
        src = self._channelModel.get_identity_by_row(index2)
        subject = thread.subject
        body = self.messages_message.toPlainText()
        parent = thread.longest
        message = objtypes.SimpleMessage('Re: '+subject, body+'\n'+54*'-'+'\n'+parent)
        self._core.send_message(src, dst, message)
        self.messages_message.setPlainText('')


class ObjectsTab(QWidget):
    def __init__(self, core, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path('data/ObjectsTab.ui'), self)
        self._core = core

        model = models.ObjectModel(self._core.inv)
        proxyModel = QSortFilterProxyModel()
        proxyModel.setSourceModel(model)
        self.tableView.setModel(proxyModel)
        # resizing
        header = self.tableView.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSortIndicator(2, Qt.DescendingOrder)


class StatusTab(QWidget):
    def __init__(self, core, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path('data/StatusTab.ui'), self)
        self._core = core

        self._core.peers.on_stats_changed.append(self.on_stats_changed)
        self._core.inv.on_stats_changed.append(self.on_stats_changed)
        self.on_stats_changed()

        self.configureNetwork.clicked.connect(self._configure_network2)

        self.about.clicked.connect(lambda: QMessageBox.about(self, 'HyperBit',
                'HyperBit is a client for the Bitmessage network.\n'
                '\n'
                'Copyright 2015-2016 HyperBit developers\n'
                'Distributed under the MIT license\n'
                '\n'
                'Please join the hyperbit channel'))
        self.aboutQt.clicked.connect(lambda: QMessageBox.aboutQt(self))

        self.show_connections()

    def show_connections(self, connections=True):
        if connections is True:
            model = models.ConnectionModel(self._core.peers)
            proxyModel = QSortFilterProxyModel()
            proxyModel.setSourceModel(model)
            self.tableView.setModel(proxyModel)

        # common resizing rule
        header = self.tableView.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(0, QHeaderView.Stretch)

        header.setSortIndicator(2, Qt.DescendingOrder)

        if connections:
            header.setSortIndicator(2, Qt.AscendingOrder)
            return

        model = models.ObjectModel(self._core.inv)
        proxyModel = QSortFilterProxyModel()
        proxyModel.setSourceModel(model)
        self.tableView.setModel(proxyModel)

    def on_stats_changed(self):
        self.objects.setText(str(self._core.inv.count()))
        self.peers.setText(str(self._core.peers.count_all()))
        self.connections.setText(str(self._core.peers.count_connected()))

    def configure_network(self):
        network_dialog = NetworkConfigDialog(self._core, self)
        try:
            __import__('socks')
        except ImportError:
            network_dialog.raTor.setEnabled(False)
        else:
            if self._core.get_config('network.proxy') == 'tor':
                network_dialog.raTor.setChecked(True)
        if self._core.get_config('network.proxy') == 'trusted':
            network_dialog.raTrusted.setChecked(True)
        network_dialog.liListen.setText(str(self._core.get_config('network.listen_port', 8444)))
        network_dialog.liHost.setText(self._core.get_config('network.tor_host', '127.0.0.1'))
        network_dialog.liPort.setText(str(self._core.get_config('network.tor_port', 9050)))
        network_dialog.liTrustedHost.setText(self._core.get_config('network.trusted_host', '127.0.0.1'))
        network_dialog.liTrustedPort.setText(str(self._core.get_config('network.trusted_port', 8444)))
        network_dialog.exec()
        if network_dialog.result():
            if network_dialog.raNone.isChecked():
                self._core.set_config('network.proxy', 'disabled')
            if network_dialog.raTor.isChecked():
                self._core.set_config('network.proxy', 'tor')
            if network_dialog.raTrusted.isChecked():
                self._core.set_config('network.proxy', 'trusted')
            self._core.set_config('network.listen_port', int(network_dialog.liListen.text()))
            self._core.set_config('network.tor_host', network_dialog.liHost.text())
            self._core.set_config('network.tor_port', int(network_dialog.liPort.text()))
            self._core.set_config('network.trusted_host', network_dialog.liTrustedHost.text())
            self._core.set_config('network.trusted_port', int(network_dialog.liTrustedPort.text()))
            return True
        else:
            return False

    def _configure_network2(self):
        if self.configure_network():
            QMessageBox.warning(self, 'HyperBit', 'Changes will not be applied until restart of HyperBit')


class MainWindow(QMainWindow):
    def __init__(self, core):
        super().__init__()
        uic.loadUi(resource_path('data/MainWindow.ui'), self)
        self._core = core

        self._status_tab = StatusTab(self._core, self)
        self.tab.addTab(ChannelsTab(self._core, self), 'Channels')
        self.tab.addTab(MessagesTab(self._core, self), 'Messages')
        # self.tab.addTab(ObjectsTab(self._core, self), 'Objects')
        self.tab.addTab(self._status_tab, 'Status')
        self.tab.setCurrentIndex(1)

        self._progressBar = QProgressBar()
        self._progressBar.setMinimum(0)
        self._progressBar.setTextVisible(True)
        self._progressBar.setFormat('Scanning (%v / %m)')
        self.statusBar.addPermanentWidget(self._progressBar, 0)
        self._progressBar.hide()
        self._core.scanner.on_change.append(self._updateProgress)

    def _updateProgress(self):
        if self._core.scanner.max < 100:
            self._progressBar.hide()
        else:
            self._progressBar.setMaximum(self._core.scanner.max)
            self._progressBar.setValue(self._core.scanner.value)
            self._progressBar.show()

    def configure_network(self):
        return self._status_tab.configure_network()
