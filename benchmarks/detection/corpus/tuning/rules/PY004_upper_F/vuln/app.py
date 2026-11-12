def f(c, u):
    c.execute(F"SELECT * FROM t WHERE a={u}")
