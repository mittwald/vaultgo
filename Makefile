
.PHONY: enable_transit
enable_transit:
	docker exec -ti vault vault secrets enable transit || echo "this is fine"

.PHONY: test
test:
	go test -v -count=1 -failfast  ./...
