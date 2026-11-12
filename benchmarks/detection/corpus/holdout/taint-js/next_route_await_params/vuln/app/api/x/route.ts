import { NextResponse } from 'next/server';
import { redirect } from 'next/navigation';
import { db } from '@/lib/db';
import { exec } from 'child_process';
import fs from 'fs';

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  await db.query("SELECT * FROM u WHERE id=" + id);
  return NextResponse.json({});
}
