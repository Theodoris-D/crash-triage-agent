# Reproducible, isolated runtime for the crash-triage agent.
#
# The agent compiles and runs intentionally-crashing C programs. Running the
# whole thing inside this container gives a disposable, network-free boundary
# around that execution (the in-process sandbox still applies resource limits).
#
#   docker build -t crash-triage-agent .
#   docker run --rm --network=none crash-triage-agent make verify
#   docker run --rm --network=none crash-triage-agent make eval report
#
# For a real model, pass the endpoint through at runtime, e.g.:
#   docker run --rm -e OPENROUTER_API_KEY=... crash-triage-agent \
#       python eval/harness.py --provider openrouter:anthropic/claude-haiku-5.5
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc gdb libc6-dev make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# stream output (and the progress bar) live instead of at exit
ENV PYTHONUNBUFFERED=1
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt pytest

COPY . .
RUN pip install --no-cache-dir -e . && python benchmark/gen_cases.py

# Default: prove the benchmark and run the offline evaluation.
CMD ["make", "verify"]
