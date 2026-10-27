// Intentionally vulnerable demo app for hardn. DO NOT DEPLOY.
const express = require("express");
const cors = require("cors");
const session = require("express-session");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");
const fs = require("fs");
const db = require("./db");

const app = express();
app.use(cors());
app.use(express.json());
app.use(session({ secret: "keyboard cat", cookie: { httpOnly: false, secure: false } }));

app.get("/users", async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  res.json(rows);
});

app.post("/ping", (req, res) => {
  exec(`ping -c 1 ${req.body.host}`, (err, stdout) => res.send(stdout));
});

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr)));
});

app.get("/download", (req, res) => {
  res.sendFile(req.query.file, { root: "/" });
});

app.get("/preview", async (req, res) => {
  const page = await fetch(req.query.url);
  res.send(await page.text());
});

app.get("/login/callback", (req, res) => {
  res.redirect(req.query.next);
});

app.get("/me", (req, res) => {
  const user = jwt.decode(req.headers.authorization);
  res.json(user);
});

app.post("/reset", (req, res) => {
  const resetToken = Math.random().toString(36).slice(2);
  res.json({ resetToken });
});

app.post("/search", async (req, res) => {
  res.json(await db.users.find(req.body));
});

app.get("/orders", async (req, res) => {
  const { customer } = req.query;
  const sql = "SELECT * FROM orders WHERE customer = '" + customer + "'";
  res.json(await db.query(sql));
});

app.post("/settings", (req, res) => {
  const prefs = req.body;
  _.merge(req.session.settings, prefs);
  res.sendStatus(204);
});

app.listen(3000);
