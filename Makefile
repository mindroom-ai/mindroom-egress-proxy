.PHONY: build check docker-build format lint pre-commit test

IMAGE ?= mindroom-egress-proxy:local

format:
	uv run ruff format .

lint:
	uv run ruff check .

test:
	uv run pytest

build:
	uv build

docker-build:
	docker build -t $(IMAGE) .

pre-commit:
	uv run pre-commit run --all-files

check: lint test build docker-build
