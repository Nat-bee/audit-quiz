.PHONY: up down logs query clean

up:
	docker compose up -d --build
	@echo "Quiz app: http://localhost:3000"
	@echo "LocalStack: http://localhost:4566"

down:
	docker compose down

logs:
	docker compose logs -f

query:
	@read -p "SQL> " sql; \
	awslocal athena start-query-execution \
		--query-string "$$sql" \
		--query-execution-context Database=security_logs \
		--result-configuration OutputLocation=s3://athena-results/

clean:
	docker compose down -v
	docker image rm athena-quiz-quiz 2>/dev/null || true
