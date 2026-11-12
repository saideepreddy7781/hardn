db.Raw("SELECT * FROM t WHERE a=?", x).Scan(&r)
