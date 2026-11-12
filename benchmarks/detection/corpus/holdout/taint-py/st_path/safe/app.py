from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse, RedirectResponse, FileResponse
import sqlite3, os, subprocess, httpx
cur = sqlite3.connect("a.db").cursor()

async def homepage(request):
    uid = request.path_params["id"]
    cur.execute("SELECT * FROM u WHERE id=?", (uid,))
