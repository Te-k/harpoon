PWD = $(shell pwd)


check:
	pytest -q
	flake8
	ruff check .

test:
	pytest

clean:
	rm -rf $(PWD)/build $(PWD)/dist $(PWD)/harpoon.egg-info

dist:
	python3 setup.py sdist bdist_wheel

upload:
	python3 -m twine upload dist/*
