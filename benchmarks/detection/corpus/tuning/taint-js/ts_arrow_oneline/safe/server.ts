const run = (req: Request) => db.query('SELECT * FROM u WHERE id=$1', [req.query.id]);
