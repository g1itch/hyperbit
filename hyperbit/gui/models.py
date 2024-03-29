# Copyright 2015-2016 HyperBit developers

from PyQt5.QtCore import QAbstractTableModel, QModelIndex, Qt, QSortFilterProxyModel, QVariant
from PyQt5.QtGui import QBrush, QColor, QFont
import binascii
from datetime import datetime
from hyperbit.gui import identicon
from hyperbit import wallet
import asyncio


class ConnectionModel(QAbstractTableModel):
    def __init__(self, peers):
        super().__init__()
        self._peers = peers
        self._connections = []
        # asyncio.get_event_loop().create_task(self._update())

    @asyncio.coroutine
    def _update(self):
        while True:
            # self.beginRemoveRows(QModelIndex(), 0, len(self._connections)-1)
            # self.endRemoveRows()
            self.beginResetModel()
            self._connections.clear()
            for connection in self._peers._connections:
                self._connections.append(connection)
            self.endResetModel()
            print('now', self.rowCount())
            yield from asyncio.sleep(1)

    def columnCount(self, QModelIndex_parent=None, *args, **kwargs):
        return 3

    def rowCount(self, QModelIndex_parent=None, *args, **kwargs):
        return len(self._connections)

    def headerData(self, index, orientation, role=None):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return ['Address', 'Port', 'User Agent'][index]
            else:
                return None
        else:
            return None

    def data(self, index, role=None):
        if role == Qt.DisplayRole:
            connection = self._connections[index.row()]
            column = index.column()
            if column == 0:
                return connection.remote_host
            elif column == 1:
                return connection.remote_port
            elif column == 2:
                return connection.remote_user_agent
        else:
            return None


class IdentityModel(QAbstractTableModel):
    def __init__(self, wal):
        super().__init__()
        self.wal = wal
        self.identities = []
        for identity in wal.identities:
            self.identities.append(identity)
        wal.on_add_identity.append(self._on_add_identity)
        wal.on_remove_identity.append(self._on_remove_identity)

    def _on_add_identity(self, identity):
        self.beginInsertRows(QModelIndex(), len(self.identities), len(self.identities))
        self.identities.append(identity)
        self.endInsertRows()

    def _on_remove_identity(self, identity):
        index = self.identities.index(identity)
        self.beginRemoveRows(QModelIndex(), index, index)
        del self.identities[index]
        self.endRemoveRows()

    def columnCount(self, QModelIndex_parent=None, *args, **kwargs):
        return 2

    def rowCount(self, QModelIndex_parent=None, *args, **kwargs):
        return len(self.identities)

    def headerData(self, index, orientation, role=None):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return ['Name', 'Address'][index]
            else:
                return None
        else:
            return None

    def data(self, index, role=Qt.DisplayRole):
        if role in (Qt.DisplayRole, Qt.EditRole, Qt.ToolTipRole):
            identity = self.identities[index.row()]
            column = index.column()
            if column == 1 or role == Qt.ToolTipRole:
                return identity.profile.address.to_str()
            elif column == 0:
                return self.wal.names.get(identity.profile.address.ripe)
        elif role == Qt.DecorationRole:
            identity = self.identities[index.row()]
            column = index.column()
            if column == 0:
                return identicon.get(identity.profile.address.to_bytes())
            else:
                return None
        elif role == Qt.ForegroundRole:
            identity = self.identities[index.row()]
            column = index.column()
            if identity.type == wallet.IdentityType.normal:
                return QBrush(Qt.black)
            elif identity.type == wallet.IdentityType.channel:
                return QBrush(Qt.darkRed)
        else:
            return None

    def flags(self, index):
        identity = self.identities[index.row()]
        column = index.column()
        if column == 0:
            if identity.type == wallet.IdentityType.normal:
                return Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsEditable
            elif identity.type == wallet.IdentityType.channel:
                return Qt.ItemIsEnabled | Qt.ItemIsSelectable
        elif column == 1:
            return Qt.ItemIsEnabled | Qt.ItemIsSelectable

    def setData(self, index, value, role=Qt.EditRole):
        if role == Qt.DisplayRole or role == Qt.EditRole:
            identity = self.identities[index.row()]
            column = index.column()
            if column == 0:
                if identity.type == wallet.IdentityType.normal:
                    self.wal.names.set(identity.profile.address.ripe, value)
                    return True
                elif identity.type == wallet.IdentityType.channel:
                    return False
            elif column == 1:
                return False
        else:
            return False

    def get_identity(self, index):
        return self.identities[index.row()]

    def get_identity_by_row(self, row):
        return self.identities[row]


class ObjectModel(QAbstractTableModel):
    def __init__(self, inv):
        super().__init__()
        self.inv = inv
        self.hashes = []
        for hash in self.inv.get_hashes():
            self.hashes.append(hash)
        inv.on_add_object.append(self._on_add_object)
        inv.on_remove_object.append(self._on_remove_object)

    def _on_add_object(self, object):
        self.beginInsertRows(QModelIndex(), len(self.hashes), len(self.hashes))
        self.hashes.append(object.hash)
        self.endInsertRows()

    def _on_remove_object(self, object):
        index = self.hashes.index(object.hash)
        self.beginRemoveRows(QModelIndex(), index, index)
        del self.hashes[index]
        self.endRemoveRows()

    def columnCount(self, QModelIndex_parent=None, *args, **kwargs):
        return 5

    def rowCount(self, QModelIndex_parent=None, *args, **kwargs):
        return len(self.hashes)

    def headerData(self, index, orientation, role=None):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return ['Hash', 'Brink', 'Expires', 'Type', 'Size'][index]
            else:
                return None
        else:
            return None

    def data(self, index, role=None):
        if role == Qt.DisplayRole:
            hash = self.hashes[index.row()]
            object = self.inv.get_object(hash)
            column = index.column()
            if column == 0:
                return binascii.hexlify(hash).decode()
            elif column == 1:
                # return binascii.hexlify(object.nonce.to_bytes(8, 'big')).decode()
                return datetime.utcfromtimestamp(max(object.brink, 0)).isoformat()
            elif column == 2:
                return datetime.utcfromtimestamp(object.expires).isoformat()
            elif column == 3:
                return '{}:{}'.format(object.type, object.version)
            elif column == 4:
                return len(object.payload)
        else:
            return None


class ThreadModel(QAbstractTableModel):
    def __init__(self, list):
        super().__init__()
        self._list = list
        self.threads = []
        for thread in list.threads:
            self.threads.append(thread)
        list.on_add_thread.append(self._on_add_thread)
        list.on_remove_thread.append(self._on_remove_thread)

    def _on_add_thread(self, thread):
        self.beginInsertRows(QModelIndex(), len(self.threads), len(self.threads))
        self.threads.append(thread)
        self.endInsertRows()

    def _on_remove_thread(self, thread):
        index = self.threads.index(thread)
        self.beginRemoveRows(QModelIndex(), index, index)
        del self.threads[index]
        self.endRemoveRows()

    def columnCount(self, QModelIndex_parent=None, *args, **kwargs):
        return 1

    def rowCount(self, QModelIndex_parent=None, *args, **kwargs):
        return len(self.threads)

    def headerData(self, index, orientation, role=None):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return ['Subject'][index]
            else:
                return None
        else:
            return None

    def data(self, index, role=None):
        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            thread = self.get_thread(index)
            column = index.column()
            if column == 0:
                return thread.subject
        elif role == Qt.DecorationRole:
            thread = self.get_thread(index)
            column = index.column()
            if column == 0:
                return identicon.get(thread.creator or thread.channel, 8)
            else:
                return None
        elif role == Qt.FontRole:
            font = QFont()
            thread = self.get_thread(index)
            if thread.unread > 0:
                font.setBold(True)
            return font
        else:
            return None

    def get_thread(self, index):
        return self.threads[index.row()]

    def get_thread_by_row(self, row):
        return self.threads[row]

