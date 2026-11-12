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
async def handler(uid: str, db: Session = Depends(get_db)):
    db.execute(text("SELECT * FROM u WHERE id=:i").bindparams(i=uid))
