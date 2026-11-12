q := "SELECT * FROM t WHERE a=$1"
db.Query(q, x)
