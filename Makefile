.PHONY: audit build check docker-build format lint pre-commit test

IMAGE ?= mindroom-egress-proxy:local

format:
	uv run ruff format .

lint:
	uv run ruff check .

test:
	uv run pytest

audit:
	uv export --locked --all-groups --no-emit-project --format requirements-txt --output-file /tmp/mindroom-egress-proxy-requirements.txt >/tmp/mindroom-egress-proxy-export.log
	uv run pip-audit --strict --progress-spinner off --disable-pip --require-hashes --requirement /tmp/mindroom-egress-proxy-requirements.txt

build:
	uv build

docker-build:
	docker build -t $(IMAGE) .

pre-commit:
	uv run pre-commit run --all-files

check: lint test audit build docker-build
