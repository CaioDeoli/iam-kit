run:
	go run ./cmd/iamkit

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v
