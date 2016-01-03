# Copyright 2015-2016 HyperBit developers


class Comment2(object):
    def __init__(self, db, rowid):
        self._db = db
        self._rowid = rowid

    @property
    def thread(self):
        thread_id = self._db.execute('select thread_id from comments where rowid = ?',
                (self._rowid,)).fetchone()[0]
        return Thread2(self._db, thread_id)

    @property
    def parent_text(self):
        return self._db.execute('select parent_text from comments where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @parent_text.setter
    def parent_text(self, parent_text):
        self._db.execute('update comments set parent_text = ? where rowid = ?',
                (parent_text, self._rowid))

    @property
    def creator(self):
        return self._db.execute('select creator from comments where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @creator.setter
    def creator(self, creator):
        self._db.execute('update comments set creator = ? where rowid = ?',
                (creator, self._rowid))

    @property
    def text(self):
        return self._db.execute('select text from comments where rowid = ?',
                (self._rowid,)).fetchone()[0]


class Thread2(object):
    def __init__(self, db, rowid):
        self._db = db
        self._rowid = rowid

    @property
    def channel(self):
        return self._db.execute('select channel from threads where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @property
    def creator(self):
        return self._db.execute('select creator from threads where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @creator.setter
    def creator(self, creator):
        self._db.execute('update threads set creator = ? where rowid = ?',
                (creator, self._rowid))

    @property
    def subject(self):
        return self._db.execute('select subject from threads where rowid = ?',
                (self._rowid,)).fetchone()[0]

    def new_comment(self, parent_text, creator, text):
        self._db.execute('update threads set unread = unread + 1 where rowid = ?',
                (self._rowid,))
        rowid = self._db.execute('insert into comments (thread_id, parent_text, creator, text) values (?, ?, ?, ?)',
                (self._rowid, parent_text, creator, text)).lastrowid
        return Comment2(self._db, rowid)

    @property
    def comments(self):
        comments = []
        for rowid, in self._db.execute('select rowid from comments where thread_id = ? order by rowid', (self._rowid,)):
            comments.append(Comment2(self._db, rowid))
        return comments

    @property
    def longest(self):
        return self._db.execute('select longest from threads where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @longest.setter
    def longest(self, longest):
        self._db.execute('update threads set longest = ? where rowid = ?',
                (longest, self._rowid))

    @property
    def unread(self):
        return self._db.execute('select unread from threads where rowid = ?',
                (self._rowid,)).fetchone()[0]

    @unread.setter
    def unread(self, unread):
        self._db.execute('update threads set unread = ? where rowid = ?',
                (unread, self._rowid))

    def __eq__(self, other):
        if isinstance(other, Thread2):
            return self._db == other._db and self._rowid == other._rowid
        else:
            return NotImplemented

class ThreadList(object):
    def __init__(self, db):
        self._db = db
        self._db.execute('create table if not exists threads (channel, creator, subject, longest, unread)')
        self._db.execute('create table if not exists comments (thread_id, parent_text, creator, text)')
        self.on_add_thread = []
        self.on_remove_thread = []

    def new_thread(self, channel, creator, subject):
        rowid = self._db.execute('insert into threads (channel, creator, subject, longest, unread) values (?, ?, ?, ?, 0)',
                (channel, creator, subject, '')).lastrowid
        thread = Thread2(self._db, rowid)
        for func in self.on_add_thread:
            func(thread)
        return thread

    def remove_thread(self, thread):
        for func in self.on_remove_thread:
            func(thread)
        self._db.execute('delete from comments '
                             'where thread_id = ?',
                             (thread._rowid,))
        self._db.execute('delete from threads '
                             'where rowid = ?',
                             (thread._rowid,))

    @property
    def threads(self):
        threads = []
        for rowid, in self._db.execute('select rowid from threads'):
            threads.append(Thread2(self._db, rowid))
        return threads
