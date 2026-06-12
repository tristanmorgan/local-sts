# local-sts

A lightweight mock AWS Security Token Service (STS) server for local development and testing.

## Overview

`local-sts` is a Go-based HTTP server that mimics AWS STS API endpoints, allowing developers to test AWS credential workflows locally without making actual calls to AWS. It decodes AWS access keys to extract account IDs and returns properly formatted XML responses matching the AWS STS API specification.

## Features

- ✅ **GetCallerIdentity** - Returns identity information from AWS credentials
- ✅ **GetAccessKeyInfo** - Returns account information for a given access key
- ✅ **Health Check** - `/health` endpoint for monitoring
- ✅ **Prometheus Metrics** - `/metrics` endpoint for observability
- ✅ **Account ID Extraction** - Decodes AWS account IDs from access keys using base32 decoding
- ✅ **Docker Support** - Ready-to-use container image

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/tristanmorgan/local-sts.git
cd local-sts

# Build the binary
go build -o local-sts

# Run the server
./local-sts
```

### Using Docker

```bash
# Build the Docker image
docker build -t local-sts .

# Run the container
docker run -p 80:80 local-sts
```

## Usage

### Starting the Server

```bash
# Default (listens on port 80)
./local-sts

# Custom port
./local-sts -listen :8080

# Display version
./local-sts -version
```

### Command-Line Options

- `-listen` - Listen address (default: `:80`)
- `-version` - Display version information

## API Endpoints

### GetCallerIdentity

Returns the identity of the caller based on AWS credentials in the Authorization header.

**Request:**
```bash
curl -X POST "http://localhost/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc" \
  -d "Action=GetCallerIdentity"
```

**Response:**
```xml
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::650104742735:user/Alice</Arn>
    <UserId>AKIAZOXKDENHR2JTNJLI</UserId>
    <Account>650104742735</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>uuid-generated-request-id</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>
```

### GetAccessKeyInfo

Returns account information for a given access key.

**Request:**
```bash
curl -X POST "http://localhost/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "Action=GetAccessKeyInfo&AccessKeyId=AKIAZOXKDENHR2JTNJLI"
```

**Response:**
```xml
<GetAccessKeyInfoResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetAccessKeyInfoResult>
    <Account>650104742735</Account>
  </GetAccessKeyInfoResult>
  <ResponseMetadata>
    <RequestId>uuid-generated-request-id</RequestId>
  </ResponseMetadata>
</GetAccessKeyInfoResponse>
```

### Health Check

**Request:**
```bash
curl http://localhost/health
```

**Response:**
```
Healthy.
```

### Metrics

Prometheus-compatible metrics endpoint.

**Request:**
```bash
curl http://localhost/metrics
```

## Development

### Running Tests

```bash
# Run all tests
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Running Benchmarks

```bash
go test -bench=. -benchmem
```

## How It Works

The server extracts AWS account IDs from access keys using a base32 decoding algorithm:

1. Extracts characters 3-12 from the access key (10 characters)
2. Decodes using AWS's base32 table
3. Shifts right by 4 bits and masks with a 40-bit mask
4. Formats as a 12-digit account ID

Invalid or malformed keys return `000000000000` as the account ID.

## Dependencies

- [github.com/google/uuid](https://github.com/google/uuid) - UUID generation for request IDs
- [github.com/prometheus/client_golang](https://github.com/prometheus/client_golang) - Prometheus metrics

## License

See [LICENSE.txt](LICENSE.txt) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Links

- **Homepage:** https://github.com/tristanmorgan/local-sts
- **Issues:** https://github.com/tristanmorgan/local-sts/issues
