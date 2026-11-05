.PHONY: all test benchmarks fetch-benchmarks run-benchmarks labels

all: test

test:
	pytest -q

labels:
	python benchmarks/generate_labels.py

fetch-benchmarks:
	python benchmarks/fetch.py

run-benchmarks:
	python benchmarks/run_benchmarks.py

benchmarks: fetch-benchmarks labels run-benchmarks

