# Copyright 2015 HyperBit developers

from hyperbit import database


class Comment2(object):
    def __init__(self, rowid):
        self._rowid = rowid

    @property
    def thread(self):
        thread_id = database.db2.execute('select thread_id from comments where rowid = ?',
                (self._rowid,)).fetchone()[0]
        return Thread2(thread_id)

    @property
    def parent_text(self):
        return database.db2.execute('select parent_text from comments where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @parent_text.setter
    def parent_text(self, parent_text):
        database.db2.execute('update comments set parent_text = ? where rowid = ?',
                (parent_text, self._rowid))

    @property
    def creator(self):
        return database.db2.execute('select creator from comments where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @creator.setter
    def creator(self, creator):
        database.db2.execute('update comments set creator = ? where rowid = ?',
                (creator, self._rowid))

    @property
    def text(self):
        return database.db2.execute('select text from comments where rowid = ?',
                (self._rowid,)).fetchone()[0]


class Thread2(object):
    def __init__(self, rowid):
        self._rowid = rowid

    @property
    def channel(self):
        return database.db2.execute('select channel from threads where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @property
    def creator(self):
        return database.db2.execute('select creator from threads where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @creator.setter
    def creator(self, creator):
        database.db2.execute('update threads set creator = ? where rowid = ?',
                (creator, self._rowid))

    @property
    def subject(self):
        return database.db2.execute('select subject from threads where rowid = ?',
                (self._rowid,)).fetchone()[0]

    def new_comment(self, parent_text, creator, text):
        database.db2.execute('update threads set unread = unread + 1 where rowid = ?',
                (self._rowid,))
        rowid = database.db2.execute('insert into comments (thread_id, parent_text, creator, text) values (?, ?, ?, ?)',
                (self._rowid, parent_text, creator, text)).lastrowid
        return Comment2(rowid)

    @property
    def comments(self):
        comments = []
        for rowid, in database.db2.execute('select rowid from comments where thread_id = ? order by rowid', (self._rowid,)):
            comments.append(Comment2(rowid))
        return comments

    @property
    def longest(self):
        return database.db2.execute('select longest from threads where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @longest.setter
    def longest(self, longest):
        database.db2.execute('update threads set longest = ? where rowid = ?',
                (longest, self._rowid))

    @property
    def unread(self):
        return database.db2.execute('select unread from threads where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @unread.setter
    def unread(self, unread):
        database.db2.execute('update threads set unread = ? where rowid = ?',
                (unread, self._rowid))

class ThreadList(object):
    def __init__(self):
        database.db2.execute('create table if not exists threads (channel, creator, subject, longest, unread)')
        database.db2.execute('create table if not exists comments (thread_id, parent_text, creator, text)')
        self.on_add_thread = []

    def new_thread(self, channel, creator, subject):
        rowid = database.db2.execute('insert into threads (channel, creator, subject, longest, unread) values (?, ?, ?, ?, 0)',
                (channel, creator, subject, '')).lastrowid
        thread = Thread2(rowid)
        for func in self.on_add_thread:
            func(thread)
        return thread

    def add_thread(self, thread):
        database.db2.execute('insert into threads (channel, creator, subject) values (?, ?, ?)',
                [b'', b'', thread.subject])
        database.db2.execute('insert into comments (thread_id, parent_text, creator, text) values (?, ?, ?, ?)',
                [-1, '', b'', thread.bodies[0]])
        self.threads.append(thread)
        for func in self.on_add_thread:
            func(thread)

    @property
    def threads(self):
        threads = []
        for rowid, in database.db2.execute('select rowid from threads'):
            threads.append(Thread2(rowid))
        return threads


class Thread(object):
    def __init__(self, identity, subject):
        self.identity = identity
        self.subject = subject
        self.bodies = []
        self.on_add_body = []
        self.on_insert_comment = []

    def insert_comment(self, index, comment):
        self.bodies.insert(index, comment)
        for func in self.on_insert_comment:
            func(index, comment)

    def add_body(self, body):
        self.bodies.append(body)
        for func in self.on_add_body:
            func(body)


class Comment(object):
    def __init__(self, text, ghost):
        self.text = text
        self.ghost = ghost
        self.on_change = []

    def set_ghost(self, ghost):
        self.ghost = ghost
        for func in self.on_change:
            func()
