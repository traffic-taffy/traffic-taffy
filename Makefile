all: package
	hatch build

testit:
	PYTHONPATH=. pytest-3

package: testit packageforce

packageforce:
	rm -rf dist
	hatch build

publish:
	hatch publish -u __token__
        # python3 -m twine upload -u __token__ dist/*

install:
	python3 setup.py install
