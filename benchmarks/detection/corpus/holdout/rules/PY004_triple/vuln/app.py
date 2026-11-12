def f(c, u):
    c.execute("""SELECT * FROM t WHERE a=""" + u)
