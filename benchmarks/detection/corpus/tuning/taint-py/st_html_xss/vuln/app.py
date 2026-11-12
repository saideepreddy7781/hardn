from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse, RedirectResponse, FileResponse
import sqlite3, os, subprocess, httpx
cur = sqlite3.connect("a.db").cursor()

async def homepage(request):
    return HTMLResponse("<h1>" + request.query_params["x"] + "</h1>")
