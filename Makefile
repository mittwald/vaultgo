
.PHONY: enable_transit
enable_transit:
	docker exec -ti vault vault secrets enable transit || echo "this is fine"

.PHONY: test
test: enable_transit
	cd pkg && go test -v -count=1 -failfast  ./...
