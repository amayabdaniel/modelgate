.PHONY: build test run docker-build

build:
	go build -o bin/modelgate .

test:
	go test ./... -v -count=1

run:
	go run . --listen=:8080 --policy=examples/policy.yaml --backend=http://localhost:8000

docker-build:
	docker build -t ghcr.io/amayabdaniel/modelgate:latest .
