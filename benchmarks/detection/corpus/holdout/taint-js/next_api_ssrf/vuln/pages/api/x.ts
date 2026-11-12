import type { NextApiRequest, NextApiResponse } from 'next';
import db from '@/lib/db';
import axios from 'axios';
import fs from 'fs';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const r = await axios.get(req.query.url as string);
}
