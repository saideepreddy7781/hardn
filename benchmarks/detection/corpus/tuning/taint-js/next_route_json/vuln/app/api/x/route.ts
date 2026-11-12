import { NextResponse } from 'next/server';
import { redirect } from 'next/navigation';
import { db } from '@/lib/db';
import { exec } from 'child_process';
import fs from 'fs';

export async function GET(request: Request) {
  const body = await request.json();
  await db.query("SELECT * FROM u WHERE id=" + body.id);
  return NextResponse.json({});
}
