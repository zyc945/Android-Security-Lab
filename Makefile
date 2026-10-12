.PHONY: setup doctor devices frida-ps check test

PYTHON ?= $(shell if [ -x /opt/homebrew/bin/python3 ]; then printf '%s' /opt/homebrew/bin/python3; else command -v python3; fi)

setup:
	$(PYTHON) -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/python -m pip install -r skills/android-security-lab/requirements.txt

doctor:
	./bin/android-lab doctor

devices:
	./bin/android-lab devices

frida-ps:
	./bin/android-lab frida-ps -ai

check:
	bash -n bin/android-lab
	bash -n skills/android-security-lab/scripts/android-lab
	./bin/android-lab help >/dev/null
	$(PYTHON) -c 'import ast, pathlib; [ast.parse(p.read_text()) for p in pathlib.Path("skills/android-security-lab/scripts").glob("*.py")]'
	git diff --check

test: check
	$(PYTHON) -m unittest discover -s tests -v
