.PHONY: test test-root test-agent run-core

test: test-root test-agent

test-root:
	go test ./...

test-agent:
	cd apps/agent && go test ./...

run-core:
	go run ./apps/core/cmd/argus-core
