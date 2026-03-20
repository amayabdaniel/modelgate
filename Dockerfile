FROM golang:1.22 AS builder
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o modelgate .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /workspace/modelgate /usr/local/bin/modelgate
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["modelgate"]
