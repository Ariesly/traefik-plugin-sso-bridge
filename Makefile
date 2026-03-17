.PHONY: lint test fmt

lint:
	golangci-lint run

test:
	go test -v ./...

fmt:
	gofmt -s -w .
