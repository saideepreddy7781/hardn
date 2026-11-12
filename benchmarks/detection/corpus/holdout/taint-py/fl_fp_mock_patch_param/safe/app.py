from unittest import mock
import sqlite3
cur = sqlite3.connect("a").cursor()

@mock.patch("a.b")
def helper(sql):
    cur.execute(sql)
