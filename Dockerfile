FROM golang:1.25-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /fang .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates chromium
ENV CHROME_BIN=/usr/bin/chromium-browser
RUN adduser -D -h /home/fang fang
USER fang
WORKDIR /home/fang
COPY --from=builder /fang .
RUN mkdir -p /home/fang/.fang/data
EXPOSE 8443
VOLUME ["/home/fang/.fang"]
