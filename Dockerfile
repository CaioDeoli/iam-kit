FROM golang:1.22 as builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o iamkit ./cmd/iamkit

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=builder /app/iamkit /app/iamkit
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/iamkit"]
