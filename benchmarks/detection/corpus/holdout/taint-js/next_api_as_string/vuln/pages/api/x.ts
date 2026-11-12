import type { NextApiRequest, NextApiResponse } from 'next';
import db from '@/lib/db';
import axios from 'axios';
import fs from 'fs';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const id = req.query.id as string;
  await db.query("SELECT * FROM u WHERE id=" + id);
}
