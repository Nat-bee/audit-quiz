COMPOSE := $(shell command -v docker > /dev/null 2>&1 && echo "docker compose" || echo "podman-compose")

UNAME_S := $(shell uname -s)
HOST_ENV := $(shell if [ -n "$$CODESPACES" ]; then echo codespaces; \
	elif grep -qi microsoft /proc/version 2>/dev/null; then echo wsl; \
	elif [ "$(UNAME_S)" = "Darwin" ]; then echo mac; \
	elif [ "$(UNAME_S)" = "Linux" ]; then echo linux; \
	elif echo "$(UNAME_S)" | grep -qE "^(MINGW|MSYS|CYGWIN)"; then echo windows; \
	else echo unknown; fi)
QUIZ_USER := $(shell git config user.name 2>/dev/null || whoami)

.PHONY: up down logs clean

up:
	HOST_ENV=$(HOST_ENV) QUIZ_USER="$(QUIZ_USER)" $(COMPOSE) up -d --build
	@echo "Quiz app: http://localhost:3000"
	@echo "Trino will be ready in ~30s"

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

clean:
	$(COMPOSE) down -v
