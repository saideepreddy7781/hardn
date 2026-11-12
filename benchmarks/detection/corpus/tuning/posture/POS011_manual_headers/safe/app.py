@app.after_request
def h(r):
    r.headers['Content-Security-Policy'] = "default-src 'self'"
    r.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return r
