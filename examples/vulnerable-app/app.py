# Intentionally vulnerable demo app for hardn. DO NOT DEPLOY.
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/user")
def user():
    con = sqlite3.connect("app.db")
    return str(con.execute(f"SELECT * FROM users WHERE id = {request.args['id']}").fetchall())


@app.route("/convert")
def convert():
    return subprocess.check_output("convert " + request.args["file"] + " out.png", shell=True)


@app.route("/import", methods=["POST"])
def import_data():
    return str(pickle.loads(request.data))


@app.route("/config", methods=["POST"])
def config():
    return str(yaml.load(request.data))


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text


@app.route("/file")
def read_file():
    return open(request.args["path"]).read()


@app.route("/go")
def go():
    return redirect(request.args["to"])


@app.route("/orders")
def orders():
    customer = request.args.get("customer", "")
    query = "SELECT * FROM orders WHERE customer = '" + customer + "'"
    return str(sqlite3.connect("app.db").execute(query).fetchall())


@app.route("/report/<name>")
def report(name):
    cmd = f"wkhtmltopdf /reports/{name}.html /tmp/out.pdf"
    os.system(cmd)
    return "ok"


def make_otp():
    otp_code = random.randint(100000, 999999)
    return otp_code


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
