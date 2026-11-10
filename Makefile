# Crash-triage agent — common tasks
PY ?= python3
export PYTHONPATH := src:eval

.PHONY: help bench verify test eval report lint docker clean install

help:
	@echo "make install   # editable install (pip install -e .)"
	@echo "make bench      # generate the benchmark C cases"
	@echo "make verify     # compile every case and check the crash/fix invariants"
	@echo "make test       # run the unit + end-to-end tests"
	@echo "make eval       # run the offline scripted evaluation (writes eval/results.db)"
	@echo "make report     # render eval/report.md from the latest run"
	@echo "make docker     # build the sandboxed runtime image"

install:
	$(PY) -m pip install -e .[dev]

bench:
	$(PY) benchmark/gen_cases.py

verify: bench
	$(PY) benchmark/verify.py

test: bench
	$(PY) -m pytest

eval: bench
	$(PY) eval/harness.py --provider scripted --security-cases 3 --notes "make eval"

report:
	$(PY) eval/report.py -o eval/report.md

clean:
	rm -rf benchmark/_build eval/results.db eval/report.md /tmp/triage_work
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

docker:
	docker build -t crash-triage-agent .
