const express = require('express');
const db = require('./db');
const { exec, execSync, spawn, execFile } = require('child_process');
const child_process = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const got = require('got');
const http = require('http');
const vm = require('vm');
const _ = require('lodash');
const deepmerge = require('deepmerge');
const app = express();
const BASE = '/srv/files';

app.get('/x', async (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM u WHERE id=$1', [id]).then((rows) => res.json(rows));
});
