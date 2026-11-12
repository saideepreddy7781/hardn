from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse, RedirectResponse, FileResponse
import sqlite3, os, subprocess, httpx
cur = sqlite3.connect("a.db").cursor()

async def homepage(request):
    import html
    return HTMLResponse("<h1>" + html.escape(request.query_params["x"]) + "</h1>")
