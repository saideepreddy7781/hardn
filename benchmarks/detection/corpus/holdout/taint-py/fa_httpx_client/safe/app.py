from typing import Annotated, Optional, List, Literal
from uuid import UUID
from fastapi import FastAPI, Request, Depends, Query, Body, Path as P
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from pydantic import BaseModel
from sqlalchemy import select, text
from myapp.db import get_db, get_settings, Session, User, Item, database
import os, subprocess, sqlite3, requests, httpx, aiohttp, asyncpg, pandas as pd
app = FastAPI()
cur = sqlite3.connect("a.db").cursor()

@app.get("/x")
async def handler(u: str):
    async with httpx.AsyncClient() as c:
        await c.get("https://api.example.com/v1", params={"q": u})
