.PHONY: build test run docker-build operator-build operator-run operator-image

build:
	go build -o bin/modelgate .

test:
	go test ./... -v -count=1

run:
	go run . --listen=:8080 --policy=examples/policy.yaml --backend=http://localhost:8000

docker-build:
	docker build -t ghcr.io/amayabdaniel/modelgate:latest .

# NIM operator (controller-runtime binary). Requires -tags k8s so the
# main modelgate proxy build stays free of k8s deps. Compiles the
# pure-Go reconciler + k8s adapter into a single deployable binary.
operator-build:
	go build -tags k8s -o bin/nim-operator ./cmd/nim-operator

operator-run:
	go run -tags k8s ./cmd/nim-operator --health-probe-bind-address=:8081

# Container image for cluster deploy. Uses Dockerfile.operator so
# controller-runtime deps don't land in the proxy image.
operator-image:
	docker build -f Dockerfile.operator -t ghcr.io/amayabdaniel/nim-operator:latest .
