def f(c, u):
    c.execute(rf"SELECT * FROM t WHERE a={u}")
