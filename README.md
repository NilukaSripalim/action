# SPA Authentication Extension API for Choreo

A Ballerina service for validating JWTs in Asgardeo's Pre-Issue Access Token webhook, designed for Single Page Applications with PKCE flow.

## 🚀 Quick Deploy to Choreo

### 1. Prerequisites
- Choreo account at https://console.choreo.dev/
- GitHub repository with this code
- Asgardeo organization for JWKS endpoint

### 2. Deploy Steps

1. **Create Component in Choreo**
   - Type: Service
   - Build Preset: Ballerina
   - Repository: Your GitHub repo
   - Build Path: `/`

2. **Set Environment Variables**
   ```
   ENABLE_DEBUG_LOG = false
   EXPECTED_ISSUER = wso2
   EXPECTED_AUDIENCE = your-spa-client-id
   JWKS_URL = https://api.asgardeo.io/t/YOUR_ORG/oauth2/jwks
   ```

3. **Deploy and Test**
   - Deploy to development environment
   - Test endpoints: `/health` and `/test-jwks`
   - Configure Asgardeo webhook with your Choreo URL

## 📡 API Endpoints

### `GET /health`
Health check with service status
```json
{
  "status": "UP",
  "service": "spa-auth-ext-api",
  "version": "1.0.0",
  "jwksConfigured": true
}
```

### `GET /test-jwks`
Test JWKS connectivity
```json
{
  "status": "JWKS_ACCESSIBLE",
  "jwksUrl": "https://...",
  "keysCount": 2
}
```

### `POST /`
Main webhook for Asgardeo
- Validates JWT from `additionalParams.jwt`
- Returns userId claim for access token

## 🔧 Configuration

The service uses these configurable values:

- `enabledDebugLog` - Enable detailed logging
- `expectedIssuer` - Expected JWT issuer (e.g., "wso2")
- `expectedAudience` - Expected JWT audience (SPA client ID)
- `jwksUrl` - JWKS endpoint for signature validation

## 🔐 JWT Validation Process

1. **Format Check** - Validates JWT structure
2. **Algorithm Check** - Supports RS256, HS256, ES256, RS512
3. **Signature Verification** - Uses JWKS endpoint
4. **Claim Validation** - Checks issuer, audience, expiration
5. **userId Extraction** - Extracts userId for access token

## 🧪 Testing

### Local Testing
```bash
bal run
curl http://localhost:9092/health
```

### Choreo Testing
```bash
curl https://your-component-dev.gateway.choreo.dev/health
```

### JWT Validation Test
```bash
curl -X POST https://your-component-dev.gateway.choreo.dev/ \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "test-123",
    "actionType": "PRE_ISSUE_ACCESS_TOKEN",
    "event": {
      "request": {
        "grantType": "authorization_code",
        "clientId": "your-spa-client-id",
        "additionalParams": [
          {
            "name": "jwt",
            "value": ["your-signed-jwt-token"]
          }
        ]
      }
    }
  }'
```

## 🔗 Integration with Asgardeo

1. **Configure SPA Application** in Asgardeo
   - Type: Single Page Application
   - Grant Types: Authorization Code + PKCE
   - Redirect URIs: Your SPA URLs

2. **Add Pre-Issue Access Token Action**
   - Endpoint: Your Choreo deployment URL
   - Authentication: None (handled by Choreo)

3. **Test End-to-End Flow**
   - SPA performs MFA → Gets signed JWT
   - SPA initiates PKCE flow with Asgardeo
   - Asgardeo calls your webhook during token issuance
   - Final token includes userId claim

## 📊 Monitoring

Choreo provides built-in:
- Request/response logs
- Performance metrics
- Error tracking
- Health monitoring

## 🔒 Security Features

- ✅ JWKS-based signature validation
- ✅ Multi-algorithm support (RS256, HS256, ES256, RS512)
- ✅ Comprehensive claim validation
- ✅ Clock skew tolerance (60 seconds)
- ✅ Input sanitization and validation
- ✅ Structured error handling
- ✅ No file system dependencies (cloud-ready)

## 🎯 Benefits

- **Zero Infrastructure** - Fully managed by Choreo
- **Auto-scaling** - Handles traffic spikes automatically
- **Security** - Built-in security and DDoS protection
- **Monitoring** - Real-time observability
- **Cost-effective** - Pay-per-use pricing model
- **Standards Compliant** - OAuth 2.1 and PKCE compatible

This service provides enterprise-grade JWT validation for SPA authentication while being optimized for Choreo's cloud-native platform.

## Flow Description

### Step 1-3: MFA Authentication
1. **User Login**: User initiates login through SPA
2. **MFA Validation**: SPA-API performs multi-factor authentication
3. **Signed JWT Creation**: Upon successful MFA, SPA-API creates a signed JWT containing:
   - `userId`: The user's unique identifier
   - `iss`: Issuer (e.g., "wso2")
   - `exp`: Expiration timestamp
   - Other standard JWT claims

### Step 4-5: PKCE Authorization Flow
1. **Authorization Request**: SPA initiates PKCE flow with Asgardeo
2. **User Authentication**: User authenticates with Asgardeo
3. **Authorization Code**: Asgardeo returns authorization code to SPA

### Step 6: Token Exchange with JWT
SPA calls Asgardeo's `/token` endpoint with:
- **Grant Type**: `authorization_code`
- **Authorization Code**: From PKCE flow
- **Code Verifier**: PKCE code verifier
- **Additional Parameters**: The signed JWT from SPA-API

### Step 7-8: Pre-Issue Access Token Webhook
1. **Asgardeo Trigger**: Before issuing the final access token, Asgardeo calls this webhook
2. **JWT Validation**: This service validates the JWT signature using the public certificate
3. **Response**: If valid, instructs Asgardeo to add `userId` as a claim

### Step 9: Final Token Issuance
1. **Enhanced Token**: Asgardeo creates the final access token with `userId` claim
2. **Token Return**: The enhanced JWT is returned to the SPA

## JWT Signing Process

### How Asgardeo Signs JWTs

Asgardeo uses standard JWT signing mechanisms:

1. **Algorithm**: Typically RS256 (RSA with SHA-256)
2. **Key Pair**: Asgardeo maintains a private/public key pair
3. **Signing Process**:
   ```
   Signature = RSA_Sign(Base64Url(Header) + "." + Base64Url(Payload), Private_Key)
   JWT = Base64Url(Header) + "." + Base64Url(Payload) + "." + Base64Url(Signature)
   ```
4. **Public Key Distribution**: Available at `https://your-org.asgardeo.io/oauth2/jwks`

### JWT Structure

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-identifier"
  },
  "payload": {
    "iss": "https://your-org.asgardeo.io/oauth2/token",
    "sub": "user-subject",
    "aud": ["your-spa-client-id"],
    "exp": 1698876543,
    "iat": 1698873543,
    "userId": "user-123",  // ← Added by this service
    "scope": "openid profile"
  }
}
```

## Validation Process

This service performs comprehensive JWT validation:

### 1. **Format Validation**
- Ensures JWT has three parts (header.payload.signature)
- Validates base64url encoding

### 2. **Signature Verification**
- Uses the provided certificate to verify the JWT signature
- Supports RS256, HS256, and ES256 algorithms

### 3. **Claim Validation**
- **Expiration (`exp`)**: Ensures token is not expired
- **Not Before (`nbf`)**: Ensures token is currently valid
- **Issuer (`iss`)**: Matches expected issuer
- **Audience (`aud`)**: Matches expected audience (if configured)
- **User ID (`userId`)**: Ensures this required claim exists

### 4. **Custom Validations**
- Clock skew tolerance (60 seconds)
- Algorithm whitelist verification
- Additional security checks

## Setup and Configuration

### 1. **Dependencies**
The service uses these Ballerina modules:
- `ballerina/http`: HTTP service framework
- `ballerina/jwt`: JWT creation and validation
- `ballerina/auth`: Authentication mechanisms
- `ballerina/crypto`: Cryptographic operations
- `ballerina/log`: Logging functionality

### 2. **Configuration**
Copy `Config.toml.template` to `Config.toml` and configure:

```toml
[spa_auth_ext_api]
enabledDebugLog = false  # Set to true for debugging
certFilePath = "/path/to/certificate.pem"
expectedIssuer = "wso2"
expectedAudience = "your-spa-client-id"  # Optional
```

### 3. **Certificate Setup**
You need the public certificate that corresponds to the private key used by your SPA-API:

```bash
# If you have a private key, extract the public certificate
openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365

# Verify certificate
openssl x509 -in certificate.pem -text -noout
```

## Running the Service

### Development
```bash
# Run with debug logging
bal run

# Run tests
bal run test_jwt.bal
```

### Production
```bash
# Build executable
bal build

# Run with production config
./target/bin/spa_auth_ext_api
```

## API Reference

### Endpoint: `POST /`

**Request Body:**
```json
{
  "requestId": "unique-request-id",
  "actionType": "PRE_ISSUE_ACCESS_TOKEN",
  "event": {
    "request": {
      "grantType": "authorization_code",
      "clientId": "your-spa-client-id",
      "additionalParams": [
        {
          "name": "jwt",
          "value": ["signed.jwt.token"]
        }
      ]
    }
  }
}
```

**Success Response (200):**
```json
{
  "actionStatus": "SUCCESS",
  "operations": [
    {
      "op": "add",
      "path": "/accessToken/claims/-",
      "value": {
        "name": "userId",
        "value": "user-123"
      }
    }
  ]
}
```

**Error Response (400):**
```json
{
  "actionStatus": "ERROR",
  "errorMessage": "JWT validation failed",
  "errorDescription": "Signature verification failed"
}
```

## Security Considerations

### 1. **Certificate Management**
- Store certificates securely
- Implement rotation procedures
- Monitor expiration dates
- Use secure file permissions (600)

### 2. **Network Security**
- Use HTTPS in production
- Implement network firewalls
- Restrict webhook access to Asgardeo IPs

### 3. **Validation Security**
- Appropriate clock skew (60 seconds)
- Algorithm whitelist (RS256, HS256, ES256)
- Comprehensive claim validation
- Rate limiting on the endpoint

### 4. **Logging and Monitoring**
- Log all validation attempts
- Monitor success/failure rates
- Set up alerting for repeated failures
- Don't log sensitive JWT content in production

## Troubleshooting

### Common Issues

1. **Certificate Not Found**
   ```
   Error: Certificate file not found
   Solution: Verify certFilePath is correct and file exists
   ```

2. **Signature Verification Failed**
   ```
   Error: Signature verification failed
   Solution: Ensure certificate matches the signing key
   ```

3. **Missing JWT Parameter**
   ```
   Error: JWT parameter not found
   Solution: Verify SPA-API includes JWT in additionalParams during token exchange
   ```

4. **Clock Skew Issues**
   ```
   Error: Token has expired
   Solution: Synchronize system clocks between services
   ```

### Debug Steps

1. **Enable Debug Logging**
   ```toml
   enabledDebugLog = true
   ```

2. **Test JWT Creation**
   ```bash
   bal run test_jwt.bal
   ```

3. **Verify Certificate**
   ```bash
   openssl x509 -in certificate.pem -text -noout
   ```

4. **Test Connectivity**
   ```bash
   curl -X POST http://localhost:9092/ -H "Content-Type: application/json" -d '{...}'
   ```

## Development and Testing

See `JWT_VALIDATION_GUIDE.md` for detailed testing instructions and `test_jwt.bal` for test utilities.

## Production Deployment

1. **Build**: `bal build`
2. **Configure**: Update `Config.toml` with production values
3. **Deploy**: Deploy to your preferred platform
4. **Configure Asgardeo**: Set webhook URL to your deployed service
5. **Monitor**: Set up logging and monitoring
6. **Test**: Verify end-to-end flow

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review logs with debug enabled
3. Verify certificate and configuration
4. Test with the provided utilities