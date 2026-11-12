q := fmt.Sprintf("SELECT * FROM t WHERE a=%s", x)
db.Query(q)
