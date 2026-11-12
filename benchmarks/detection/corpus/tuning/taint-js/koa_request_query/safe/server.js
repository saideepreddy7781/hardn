const Router = require('koa-router');
const router = new Router();
const db = require('./db');

router.get('/x', async (ctx) => {
  const id = ctx.request.query.id;
  await db.query('SELECT * FROM u WHERE id=$1', [id]);
});
