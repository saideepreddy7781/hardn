const Router = require('koa-router');
const router = new Router();
const db = require('./db');

router.get('/x', async (ctx) => {
  ctx.body = '<h1>' + ctx.query.x + '</h1>';
});
