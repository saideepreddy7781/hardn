import express, { Request, Response } from 'express';
import db from './db';
import { exec } from 'child_process';
const app = express();

app.get('/x', async (req: Request, res: Response): Promise<void> => {
  this.id = req.query.id as string;
  db.query("SELECT * FROM u WHERE id=" + this.id);
});
