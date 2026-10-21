.PHONY: test bench

test:
	python3 -m unittest -v test_all

bench:
	python3 bench.py
