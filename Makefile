.PHONY: test lint demo dev pyz binary dist clean

test:
	python3 -m unittest discover -s tests

lint:
	ruff check .

dev:            ## editable install; PEP 660 editable installs need pip 21.3 or newer
	python3 -m pip install --upgrade "pip>=21.3"
	python3 -m pip install -e .

demo:
	python3 -m hardn examples/vulnerable-app --no-external

pyz:            ## single-file app, needs only python3 on the target machine
	python3 scripts/build_pyz.py

binary:         ## standalone executable for this OS (pip install pyinstaller)
	pyinstaller --onefile --name hardn --paths . packaging/entry.py

dist:           ## wheel + sdist + pyz for a GitHub release (pip install build)
	python3 -m build
	python3 scripts/build_pyz.py

clean:
	rm -rf build dist *.egg-info hardn.spec .hardn examples/vulnerable-app/.hardn
