PY ?= .venv/bin/python
export PATH := /Applications/Docker.app/Contents/Resources/bin:$(PATH)

.PHONY: setup images batfish lab-up lab-down verify test probe requests eval-template eval-llm

setup:            ## venv + package
	uv venv --python 3.12 && uv pip install -e ".[dev]"

images:           ## lab images (FRR router, Alpine host)
	docker build -t netchange-frr:1 lab/router
	docker build -t netchange-host:1 lab/host

batfish:          ## Batfish service on localhost:9996
	docker rm -f batfish 2>/dev/null || true
	docker run -d --name batfish -p 9996:9996 -p 9997:9997 batfish/allinone:latest

lab-up:           ## deploy the 12-node Containerlab lab and push the baseline
	$(PY) -m netchange.cli lab up

lab-down:
	$(PY) -m netchange.cli lab down

verify:           ## committed network vs every invariant
	$(PY) -m netchange.cli verify

test:             ## unit tests (+ Batfish tests when the service is up)
	$(PY) -m pytest -q

probe:            ## Batfish-vs-Linux fidelity for iptables constructs
	$(PY) scripts/probe_batfish_iptables.py

requests:         ## rebuild + relabel the request set
	$(PY) scripts/make_requests.py && $(PY) scripts/label_requests.py

eval-template:    ## no-LLM evaluation (gold intents), free
	$(PY) -m netchange.evaluate --generator template --configs full,live-only,llm-only

eval-llm:         ## Claude evaluation (costs API credits)
	$(PY) -m netchange.evaluate --generator llm --configs llm-only,+lint,+batfish,+intent,+repair,full
