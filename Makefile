COMPOSE := $(shell command -v docker > /dev/null 2>&1 && echo "docker compose" || echo "podman-compose")

.PHONY: up down logs clean

up:
	$(COMPOSE) up -d --build
	@echo "Quiz app: http://localhost:3000"
	@echo "Trino will be ready in ~30s"

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

clean:
	$(COMPOSE) down -v
