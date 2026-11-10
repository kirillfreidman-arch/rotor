.PHONY: build test bench demo lint

build:
	go build -o bin/ ./cmd/...

test:
	go test -race ./...

bench:
	go test -run xxx -bench . -benchtime 3000x ./internal/proxy

demo:
	./scripts/demo.sh

lint:
	gofmt -l . && go vet ./...
