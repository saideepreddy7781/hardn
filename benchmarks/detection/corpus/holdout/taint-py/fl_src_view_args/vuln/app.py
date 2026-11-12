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


@app.route("/x")
def handler():
    uid = request.view_args["id"]
    cur.execute("SELECT * FROM u WHERE id=" + uid)
