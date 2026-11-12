from flask import Flask, request, redirect, abort, send_file, render_template, render_template_string, url_for, make_response, Response
from markupsafe import Markup
from werkzeug.utils import secure_filename, safe_join
from jinja2 import Environment
from pathlib import Path
import os, subprocess, sqlite3, shlex, pickle, yaml, requests, html, httpx, urllib.request, marshal, shutil, json, ast, io, base64, asyncio

app = Flask(__name__)
cur = sqlite3.connect("a.db").cursor()
BASE = "/srv/files"
ALLOWED = {"a", "b"}
def build(u):
    return "SELECT * FROM u WHERE id=" + u

def build_static(u):
    return "SELECT * FROM u WHERE id=1"


@app.route("/x")
def handler():
    q = build_static(request.args["id"])
    cur.execute(q)
