# local-sts

A lightweight mock AWS Security Token Service (STS) server for local development and testing.

## Overview

`local-sts` is a Go-based HTTP server that mimics AWS STS API endpoints, allowing developers to test AWS credential workflows locally without making actual calls to AWS. It decodes AWS access keys to extract account IDs and returns properly formatted XML responses matching the AWS STS API specification.

## Features

- ✅ **GetCallerIdentity** - Returns identity information from AWS credentials
- ✅ **GetAccessKeyInfo** - Returns account information for a given access key
- ✅ **GetSessionToken** - Returns temporary security credentials for AWS API requests
- ✅ **GetFederationToken** - Returns temporary security credentials for federated users
- ✅ **AssumeRole** - Returns temporary security credentials for assuming an IAM role
- ✅ **Health Check** - `/health` endpoint for monitoring
- ✅ **Prometheus Metrics** - `/metrics` endpoint for observability

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

### GetSessionToken

Returns temporary security credentials for AWS API requests. Session tokens are valid for 12 hours.

**Request:**
```bash
curl -X POST "http://localhost/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc" \
  -d "Action=GetSessionToken"
```

**Response:**
```xml
<GetSessionTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetSessionTokenResult>
    <Credentials>
      <AccessKeyId>ASIAZOXKDENHR2JTNJLI</AccessKeyId>
      <SessionToken>base64-encoded-session-token</SessionToken>
      <SecretAccessKey>base64-encoded-secret-key</SecretAccessKey>
      <Expiration>2026-06-18T12:30:00Z</Expiration>
    </Credentials>
  </GetSessionTokenResult>
  <ResponseMetadata>
    <RequestId>uuid-generated-request-id</RequestId>
  </ResponseMetadata>
</GetSessionTokenResponse>
```

### GetFederationToken

Returns temporary security credentials for federated users. Federation tokens are valid for 1 hour.

**Request:**
```bash
curl -X POST "http://localhost/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc" \
  -d "Action=GetFederationToken"
```

**Response:**
```xml
<GetFederationTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetFederationTokenResult>
    <Credentials>
      <SecretAccessKey>base64-encoded-secret-key</SecretAccessKey>
      <SessionToken>base64-encoded-session-token</SessionToken>
      <Expiration>2026-06-18T01:30:00Z</Expiration>
      <AccessKeyId>ASIAZOXKDENHR2JTNJLI</AccessKeyId>
    </Credentials>
    <FederatedUser>
      <Arn>arn:aws:sts::650104742735:federated-user/Alice</Arn>
      <FederatedUserId>650104742735:Alice</FederatedUserId>
    </FederatedUser>
    <PackedPolicySize>6</PackedPolicySize>
  </GetFederationTokenResult>
  <ResponseMetadata>
    <RequestId>uuid-generated-request-id</RequestId>
  </ResponseMetadata>
</GetFederationTokenResponse>
```

### AssumeRole

Returns temporary security credentials for assuming an IAM role. Assumed role credentials are valid for 1 hour.

**Request:**
```bash
curl -X POST "http://localhost/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc" \
  -d "Action=AssumeRole"
```

**Response:**
```xml
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <SourceIdentity>Alice</SourceIdentity>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::650104742735:assumed-role/demo/TestAR</Arn>
      <AssumedRoleId>AROAZOXKDENHR2JTNJLI:TestAR</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAZOXKDENHR2JTNJLI</AccessKeyId>
      <SecretAccessKey>base64-encoded-secret-key</SecretAccessKey>
      <SessionToken>base64-encoded-session-token</SessionToken>
      <Expiration>2026-06-18T01:30:00Z</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>uuid-generated-request-id</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>
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

## Credential Expiration Times

The mock STS server returns temporary credentials with the following expiration times:

- **GetSessionToken**: 12 hours
- **GetFederationToken**: 1 hour
- **AssumeRole**: 1 hour

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