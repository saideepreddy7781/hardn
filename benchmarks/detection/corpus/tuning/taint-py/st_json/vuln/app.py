from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse, RedirectResponse, FileResponse
import sqlite3, os, subprocess, httpx
cur = sqlite3.connect("a.db").cursor()

async def homepage(request):
    b = await request.json()
    cur.execute(f"SELECT * FROM u WHERE id={b['id']}")
