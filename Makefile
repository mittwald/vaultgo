.PHONY: test
test:
	go test -v -count=1 -failfast  ./...

.PHONY: lint
lint:
	docker run --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v1.50.1 golangci-lint run -v
