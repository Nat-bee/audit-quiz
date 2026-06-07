.PHONY: up down logs run clean

up:
	docker compose up -d --build
	@echo "Quiz app: http://localhost:3000"

down:
	docker compose down

logs:
	docker compose logs -f

run:
	DATA_DIR=./data python app/main.py

clean:
	docker compose down -v
	docker image rm athena-quiz-quiz 2>/dev/null || true
