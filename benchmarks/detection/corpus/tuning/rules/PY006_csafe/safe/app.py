def f(b):
    return yaml.load(b, Loader=yaml.CSafeLoader)
