import express, { Request, Response } from 'express';
import db from './db';
import { exec } from 'child_process';
const app = express();

app.get('/x', async (req: Request, res: Response): Promise<void> => {
  const id = <string>req.query.id;
  db.query('SELECT * FROM u WHERE id=$1', [id]);
});
