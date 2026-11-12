const run = (req: Request) => db.query("SELECT * FROM u WHERE id=" + req.query.id);
