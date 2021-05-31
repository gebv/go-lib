
test:
	go test -v -timeout 5m -race -coverprofile=coverage.txt -covermode=atomic -bench=. -run=. ./...
.PHONY: test
