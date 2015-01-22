#!/usr/bin/env python
# pylint: disable=missing-docstring
# pylint: disable=bad-continuation

import sqlite3

class DbConn(object):
    def __init__(self, dbfile):
        self.con = sqlite3.connect(dbfile)
        self.con.set_authorizer(self.__authorize)
        self.be_safe = False
        self.cur = self.con.cursor()

    def execute(self, query, params=()):
        self.cur.execute(query, params)
        return self.cur

    def execute_safe(self, query, params=()):
        self.be_safe = True
        try:
            self.cur.execute(query, params)
        finally:
            self.be_safe = False
        return self.cur

    def executescript(self, script):
        self.cur.executescript(script)

    def fetchone(self):
        return self.cur.fetchone()

    def fetchall(self):
        return self.cur.fetchall()

    def commit(self):
        return self.con.commit()

    @property
    def rowcount(self):
        return self.cur.rowcount

    @property
    def lastrowid(self):
        return self.cur.lastrowid

    def __authorize(self, atype, arg1, arg2, table, src): # pylint: disable=too-many-arguments
        _ = (arg1, arg2, table, src)
        if not self.be_safe:
            return sqlite3.SQLITE_OK

        # NOTE: Function and Recursive are not in sqlite3 package
        # Are they needed?
        if (atype == sqlite3.SQLITE_ANALYZE or
            atype == sqlite3.SQLITE_READ or
            atype == sqlite3.SQLITE_OK or
            atype == sqlite3.SQLITE_SELECT):
            return sqlite3.SQLITE_OK

        return sqlite3.SQLITE_DENY


