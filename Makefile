PWD = $(shell pwd)


check:
	ruff check .

test:
	pytest

clean:
	rm -rf $(PWD)/build $(PWD)/dist $(PWD)/harpoon.egg-info

dist:
	python3 -m build

upload:
	python3 -m twine upload dist/*
