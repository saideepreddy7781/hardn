import { NextResponse } from 'next/server';
import { redirect } from 'next/navigation';
import { db } from '@/lib/db';
import { exec } from 'child_process';
import fs from 'fs';

export async function GET(request: Request) {
  const f = await request.formData();
  const d = f.get('d');
  exec('ls ' + d);
  return NextResponse.json({});
}
