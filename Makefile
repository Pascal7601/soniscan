-include .env
export

.PHONY: help up down migrate run worker test lint format typecheck api-schema api-check check

help:        ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

up:          ## Start Postgres and Redis
	docker compose up -d --wait

down:        ## Stop local services
	docker compose down

migrate:     ## Apply migrations as the owner role
	cd backend && DATABASE_URL=$(MIGRATE_DATABASE_URL) python manage.py migrate

run:         ## Run the API (as the least-privilege role)
	cd backend && python manage.py runserver

worker:      ## Run the Celery worker
	cd backend && celery -A config worker -l info

test:        ## Backend tests
	cd backend && pytest

lint:        ## Lint, format check, architecture rules
	cd backend && ruff check . && ruff format --check . && lint-imports

typecheck:   ## Static type checks (backend and frontend)
	cd backend && mypy .
	cd frontend && npm run typecheck

format:      ## Auto-format
	cd backend && ruff check --fix . && ruff format .

api-schema:  ## Regenerate the OpenAPI file and the typed frontend client
	cd backend && python manage.py spectacular --file openapi.yaml --validate
	cd frontend && npm run gen:api

api-check:   ## Fail if the committed API contract is stale
	$(MAKE) api-schema
	git diff --exit-code backend/openapi.yaml frontend/src/lib/api/schema.d.ts

check: lint typecheck test  ## Everything CI runs, locally
