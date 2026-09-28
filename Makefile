.PHONY: test build up demo

test:
	go test ./...

build:
	docker compose build

up:
	docker compose up --build -d server

demo:
	docker compose up --build -d server
	docker compose run --rm client
