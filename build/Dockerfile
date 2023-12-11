FROM golang:1.21.5-alpine

# Create directory for our app inside the container
WORKDIR /app

# Prepare dependencies
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copy code /to the container image.
COPY . ./

# Build the binary and call it "docker-ssi-service"
RUN go build -tags jwx_es256k -o /docker-ssi-service ./cmd/ssiservice

EXPOSE 3000

CMD [ "/docker-ssi-service" ]