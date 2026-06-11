COMPOSE := $(shell if command -v docker >/dev/null 2>&1; then echo "docker compose"; \
	elif command -v podman-compose >/dev/null 2>&1; then echo "podman-compose"; \
	elif command -v nerdctl >/dev/null 2>&1; then echo "nerdctl compose"; \
	else echo "podman-compose"; fi)

UNAME_S := $(shell uname -s)
HOST_ENV := $(shell if [ -n "$$CODESPACES" ]; then echo codespaces; \
	elif grep -qi microsoft /proc/version 2>/dev/null; then echo wsl; \
	elif [ "$(UNAME_S)" = "Darwin" ]; then echo mac; \
	elif [ "$(UNAME_S)" = "Linux" ]; then sed -n "s/^ID=//p" /etc/os-release 2>/dev/null | tr -d '"' | grep . || echo linux; \
	elif echo "$(UNAME_S)" | grep -qE "^(MINGW|MSYS|CYGWIN)"; then echo windows; \
	else echo unknown; fi)
DOCKER_CONTEXT := $(shell docker context show 2>/dev/null)
CONTAINER_RUNTIME := $(shell if command -v docker >/dev/null 2>&1; then \
	if echo "$(DOCKER_CONTEXT)" | grep -qi colima; then echo colima; \
	elif echo "$(DOCKER_CONTEXT)" | grep -qi lima; then echo lima; \
	elif echo "$(DOCKER_CONTEXT)" | grep -qi orbstack; then echo orbstack; \
	elif echo "$(DOCKER_CONTEXT)" | grep -qi rancher; then echo rancher; \
	else echo docker; fi; \
	elif command -v podman-compose >/dev/null 2>&1; then echo podman; \
	elif command -v nerdctl >/dev/null 2>&1; then echo nerdctl; \
	else echo podman; fi)
QUIZ_USER := $(shell git config user.name 2>/dev/null || whoami)

.PHONY: up down logs clean

up:
	HOST_ENV=$(HOST_ENV) CONTAINER_RUNTIME=$(CONTAINER_RUNTIME) QUIZ_USER="$(QUIZ_USER)" $(COMPOSE) up -d --build
	@echo "Quiz app: http://localhost:3000"
	@echo "Trino will be ready in ~30s"

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

clean:
	$(COMPOSE) down -v
