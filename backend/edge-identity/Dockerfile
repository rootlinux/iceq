FROM golang:1.26.5-alpine AS builder
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/edge-identity ./edge-identity
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /edge-identity ./edge-identity

FROM scratch
COPY --from=builder /edge-identity /edge-identity
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/edge-identity"]
