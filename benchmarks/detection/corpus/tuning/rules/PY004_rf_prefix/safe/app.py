def f(c, u):
    c.execute(r"SELECT * FROM t WHERE a=?", [u])
