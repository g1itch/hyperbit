# Copyright 2015-2016 HyperBit developers


class Comment2(object):
    def __init__(self, db, rowid):
        self._db = db
        self._rowid = rowid

    @property
    def thread(self):
        thread_id = self._db.execute(
            'SELECT thread_id FROM comments WHERE rowid = ?', (self._rowid,)
        ).fetchone()[0]
        return Thread2(self._db, thread_id)

    @property
    def parent_text(self):
        return self._db.execute(
            'SELECT parent_text FROM comments WHERE rowid = ?', (self._rowid,)
        ).fetchone()[0]

    @parent_text.setter
    def parent_text(self, parent_text):
        self._db.execute(
            'UPDATE comments SET parent_text = ? WHERE rowid = ?',
            (parent_text, self._rowid))

    @property
    def creator(self):
        return self._db.execute(
            'SELECT creator FROM comments WHERE rowid = ?',
            (self._rowid,)
        ).fetchone()[0]

    @creator.setter
    def creator(self, creator):
        self._db.execute(
            'UPDATE comments SET creator = ? WHERE rowid = ?',
            (creator, self._rowid))

    @property
    def text(self):
        return self._db.execute(
            'SELECT text FROM comments WHERE rowid = ?', (self._rowid,)
        ).fetchone()[0]


class Thread2(object):
    def __init__(self, db, rowid):
        self._db = db
        self._rowid = rowid

    @property
    def channel(self):
        return self._db.execute(
            'SELECT channel FROM threads WHERE rowid = ?', (self._rowid,)
        ).fetchone()[0]

    @property
    def creator(self):
        return self._db.execute(
            'SELECT creator FROM threads WHERE rowid = ?', (self._rowid,)
        ).fetchone()[0]

    @creator.setter
    def creator(self, creator):
        self._db.execute(
            'UPDATE threads SET creator = ? WHERE rowid = ?',
            (creator, self._rowid))

    @property
    def subject(self):
        return self._db.execute(
            'SELECT subject FROM threads WHERE rowid = ?', (self._rowid,)
        ).fetchone()[0]

    def new_comment(self, parent_text, creator, text):
        self._db.execute(
            'UPDATE threads SET unread = unread + 1 WHERE rowid = ?',
            (self._rowid,))
        rowid = self._db.execute(
            'INSERT INTO comments (thread_id, parent_text, creator, text)'
            ' VALUES (?, ?, ?, ?)', (self._rowid, parent_text, creator, text)
        ).lastrowid
        return Comment2(self._db, rowid)

    @property
    def comments(self):
        comments = []
        for rowid, in self._db.execute(
            'SELECT rowid FROM comments WHERE thread_id = ? ORDER BY rowid',
            (self._rowid,)
        ):
            comments.append(Comment2(self._db, rowid))
        return comments

    @property
    def longest(self):
        return self._db.execute(
            'SELECT longest FROM threads WHERE rowid = ?', (self._rowid,)
        ).fetchone()[0]

    @longest.setter
    def longest(self, longest):
        self._db.execute(
            'UPDATE threads SET longest = ? WHERE rowid = ?',
            (longest, self._rowid))

    @property
    def unread(self):
        return self._db.execute(
            'SELECT unread FROM threads WHERE rowid = ?', (self._rowid,)
        ).fetchone()[0]

    @unread.setter
    def unread(self, unread):
        self._db.execute(
            'UPDATE threads SET unread = ? WHERE rowid = ?',
            (unread, self._rowid))

    def __eq__(self, other):
        if isinstance(other, Thread2):
            return self._db == other._db and self._rowid == other._rowid
        else:
            return NotImplemented


class ThreadList(object):
    def __init__(self, db):
        self._db = db
        self._db.execute(
            'CREATE TABLE IF NOT EXISTS threads'
            ' (channel, creator, subject, longest, unread)')
        self._db.execute(
            'CREATE TABLE IF NOT EXISTS comments'
            ' (thread_id, parent_text, creator, text)')
        self.on_add_thread = []
        self.on_remove_thread = []

    def new_thread(self, channel, creator, subject):
        rowid = self._db.execute(
            'INSERT INTO threads (channel, creator, subject, longest, unread)'
            ' VALUES (?, ?, ?, ?, 0)', (channel, creator, subject, '')
        ).lastrowid
        thread = Thread2(self._db, rowid)
        for func in self.on_add_thread:
            func(thread)
        return thread

    def remove_thread(self, thread):
        for func in self.on_remove_thread:
            func(thread)
        self._db.execute(
            'DELETE FROM comments WHERE thread_id = ?', (thread._rowid,))
        self._db.execute(
            'DELETE FROM threads WHERE rowid = ?', (thread._rowid,))

    @property
    def threads(self):
        threads = []
        for rowid, in self._db.execute('SELECT rowid FROM threads'):
            threads.append(Thread2(self._db, rowid))
        return threads
