.PHONY: up down logs clean

up:
	docker compose up -d --build
	@echo "Quiz app: http://localhost:3000"
	@echo "Trino will be ready in ~30s"

down:
	docker compose down

logs:
	docker compose logs -f

clean:
	docker compose down -v
	docker image rm athena-quiz-quiz 2>/dev/null || true
