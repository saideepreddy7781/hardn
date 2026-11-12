def f(job, u):
    job.execute(f"retry {u}")
