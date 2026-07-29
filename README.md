# local-sts

A lightweight mock AWS Security Token Service (STS) and IAM server for local development and testing.

## Overview

`local-sts` is a Go-based HTTP server that mimics AWS STS and IAM API endpoints, allowing developers to test AWS credential workflows locally without making actual calls to AWS. It decodes AWS access keys to extract account IDs and returns properly formatted XML responses matching the AWS API specifications.

## Features

### STS Actions
- ✅ **GetCallerIdentity** - Returns identity information from AWS credentials
- ✅ **GetAccessKeyInfo** - Returns account information for a given access key
- ✅ **GetSessionToken** - Returns temporary security credentials for AWS API requests (12-hour validity)
- ✅ **GetFederationToken** - Returns temporary security credentials for federated users (1-hour validity)
- ✅ **AssumeRole** - Returns temporary security credentials for assuming an IAM role (1-hour validity)

### IAM Actions
- ✅ **GetUser** - Returns information about the specified IAM user
- ✅ **GetRole** - Returns information about the specified IAM role
- ✅ **ListUsers** - Lists IAM users in the account
- ✅ **ListAccessKeys** - Lists access keys for the specified user
- ✅ **ListRoles** - Lists IAM roles in the account
- ✅ **CreateAccessKey** - Creates a new AWS access key and secret access key for the specified user
- ✅ **DeleteAccessKey** - Deletes the specified access key and returns AWS-style response metadata
- ✅ **DeleteUser** - Deletes the specified IAM user and returns AWS-style response metadata
- ✅ **DeleteRole** - Deletes the specified IAM role and returns AWS-style response metadata

### Additional Features
- ✅ **Health Check** - `/health` endpoint for monitoring
- ✅ **Prometheus Metrics** - `/metrics` endpoint for observability
- ✅ **Mode Restrictions** - Run in STS-only or IAM-only mode

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
docker run -p 8080:8080 local-sts
```

## Usage

### Starting the Server

```bash
# Default (listens on port 8080)
./local-sts

# Custom port
./local-sts -listen :8080

# STS actions only
./local-sts -sts-only

# IAM actions only
./local-sts -iam-only

# Display version
./local-sts -version
```

### Command-Line Options

- `-listen` - Listen address (default: `:8080`)
- `-version` - Display version information
- `-sts-only` - Serve only STS actions (GetCallerIdentity, GetAccessKeyInfo, GetSessionToken, GetFederationToken, AssumeRole)
- `-iam-only` - Serve only IAM actions (GetUser, GetRole, ListUsers, ListAccessKeys, ListRoles, CreateAccessKey, DeleteAccessKey, DeleteUser, DeleteRole)

**Note:** The `-sts-only` and `-iam-only` flags are mutually exclusive.

## API Endpoints

All API calls are made via HTTP POST to the root endpoint (`/`) with the `Action` parameter specifying the desired operation.

### STS Endpoints

- **GetCallerIdentity** - Returns the identity of the caller based on AWS credentials in the Authorization header
- **GetAccessKeyInfo** - Returns account information for a given access key (via `AccessKeyId` parameter)
- **GetSessionToken** - Returns temporary security credentials (12-hour validity)
- **GetFederationToken** - Returns temporary security credentials for federated users (1-hour validity)
- **AssumeRole** - Returns temporary security credentials for assuming an IAM role (1-hour validity)

### IAM Endpoints

- **GetUser** - Returns information about the IAM user
- **GetRole** - Returns information about the IAM role
- **ListUsers** - Lists IAM users in the account
- **ListAccessKeys** - Lists access keys for the user
- **ListRoles** - Lists IAM roles in the account
- **CreateAccessKey** - Creates a new AWS access key and secret access key for the specified user
- **DeleteAccessKey** - Deletes an IAM access key
- **DeleteUser** - Deletes an IAM user
- **DeleteRole** - Deletes an IAM role

### Monitoring Endpoints

- **Health Check** - `GET /health` - Returns "Healthy." for health monitoring
- **Metrics** - `GET /metrics` - Prometheus-compatible metrics endpoint

## How It Works

The server extracts AWS access keys from the Authorization header and decodes them to:
- Extract the 12-digit AWS account ID using base32 decoding
- Generate fake user names from a list of cryptographic protocol participant names (Alice, Bob, Carol, etc.)
- Return properly formatted XML responses matching AWS API specifications

All responses include:
- Unique request IDs (UUIDs)
- Proper AWS XML namespaces
- Realistic credential formats and ARNs

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
