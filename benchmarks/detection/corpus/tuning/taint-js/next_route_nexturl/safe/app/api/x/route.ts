import { NextResponse } from 'next/server';
import { redirect } from 'next/navigation';
import { db } from '@/lib/db';
import { exec } from 'child_process';
import fs from 'fs';

export async function GET(request: NextRequest) {
  const id = request.nextUrl.searchParams.get('id');
  await db.query('SELECT * FROM u WHERE id=$1', [id]);
  return NextResponse.json({});
}
