import { NextResponse } from 'next/server';
import { redirect } from 'next/navigation';
import { db } from '@/lib/db';
import { exec } from 'child_process';
import fs from 'fs';

export async function GET(req: Request) {
  const body = await req.json();
  await db.query("SELECT * FROM u WHERE id=" + body.id);
  return NextResponse.json({});
}
