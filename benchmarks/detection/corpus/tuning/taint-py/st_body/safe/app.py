from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse, RedirectResponse, FileResponse
import sqlite3, os, subprocess, httpx
cur = sqlite3.connect("a.db").cursor()

async def homepage(request):
    b = await request.body()
    await httpx.AsyncClient().post("https://api.example.com/v1", content=b)
