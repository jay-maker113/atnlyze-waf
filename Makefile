install:
	pip install -r requirements.txt

test:
	pytest -q

lint:
	flake8 src tests

run:
	uvicorn src.atnlyze.api.app:app --reload