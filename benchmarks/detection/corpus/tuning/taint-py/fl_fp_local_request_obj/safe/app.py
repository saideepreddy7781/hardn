import sqlite3
cur = sqlite3.connect("a").cursor()

def worker():
    request = load_job_from_disk()
    cur.execute(request.body)
