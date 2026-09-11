PWD = $(shell pwd)


check:
	#pytest -q
	flake8
	ruff check .
	black --check .
	mypy .

test:
	pytest

clean:
	rm -rf $(PWD)/build $(PWD)/dist $(PWD)/harpoon.egg-info

dist:
	python3 -m build

upload:
	python3 -m twine upload dist/*
