import ballerina/http;
import ballerina/log;
import ballerina/time;
import ballerina/jwt;

configurable string certFilePath = ?;
configurable string jwtIssuer = "wso2";
configurable int clockSkew = 60;

service / on new http:Listener(9092) {

    resource function post actionchoreomfavalidation(@http:Payload RequestBody payload) 
            returns SuccessResponse|FailedResponse|ErrorResponse {
        
        log:printInfo("Received pre-issue access token action request");
        
        // Validate action type
        if payload.actionType != PRE_ISSUE_ACCESS_TOKEN {
            log:printError("Invalid action type received");
            return {
                actionStatus: FAILED,
                failureReason: "invalid_request",
                failureDescription: "Only PRE_ISSUE_ACCESS_TOKEN action type is supported"
            };
        }
        
        // Extract JWT from additional parameters
        string|error jwtToken = extractJWTFromParams(payload);
        if jwtToken is error {
            log:printError("Failed to extract JWT token: " + jwtToken.message());
            return {
                actionStatus: FAILED,
                failureReason: "invalid_request",
                failureDescription: "JWT token is required in additionalParams but was not found"
            };
        }
        
        // Validate JWT signature
        jwt:Payload|error jwtPayload = validateJWTSignature(jwtToken);
        if jwtPayload is error {
            log:printError("JWT validation failed: " + jwtPayload.message());
            return {
                actionStatus: FAILED,
                failureReason: "invalid_grant",
                failureDescription: "JWT signature validation failed: " + jwtPayload.message()
            };
        }
        
        // Extract userId from validated JWT
        string|error userId = extractUserIdFromJWT(jwtPayload);
        if userId is error {
            log:printError("Failed to extract userId from JWT: " + userId.message());
            return {
                actionStatus: FAILED,
                failureReason: "invalid_token",
                failureDescription: "userId claim not found in validated JWT"
            };
        }
        
        // Extract issuer from access token claims for metadata
        string issuer = extractIssuer(payload);
        string jwksEndpoint = generateJWKSEndpoint(issuer);
        string timestamp = time:utcToString(time:utcNow());

        log:printInfo(string `JWT validated successfully - User: ${userId}, Issuer: ${issuer}`);

        // Build operations array to modify the access token
        Operations[] operations = [];

        // Add userId claim from validated JWT
        operations.push({
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "userId",
                value: userId
            }
        });

        // Add validation metadata
        string validationMetadata = string `{"requestValidated":"true","issuer":"${issuer}","jwksEndpoint":"${jwksEndpoint}","timestamp":"${timestamp}","jwtValidated":"true","note":"JWT signature validated successfully using certificate"}`;
        operations.push({
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "validationMetadata",
                value: validationMetadata
            }
        });

        // Add tenant/organization name if available
        string? tenantName = extractTenantName(payload);
        if tenantName is string {
            operations.push({
                op: "add",
                path: "/accessToken/claims/-",
                value: {
                    name: "tenantName",
                    value: tenantName
                }
            });
        }

        // Add grant type for auditing
        string grantType = extractGrantType(payload);
        operations.push({
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "grantType",
                value: grantType
            }
        });

        log:printInfo("Successfully processed pre-issue action for user: " + userId);
        
        return {
            actionStatus: SUCCESS,
            operations: operations
        };
    }
}

// Extract JWT token from request additional parameters
function extractJWTFromParams(RequestBody payload) returns string|error {
    Event? event = payload.event;
    if event is () {
        return error("No event object in payload");
    }

    Request? request = event.request;
    if request is () {
        return error("No request object in event");
    }

    map<string[]>? additionalParams = request.additionalParams;
    if additionalParams is () {
        return error("No additionalParams in request");
    }

    string[]? jwtValues = additionalParams["jwt"];
    if jwtValues is () || jwtValues.length() == 0 {
        return error("JWT parameter not found in additionalParams");
    }

    log:printInfo("JWT token extracted from request parameters");
    return jwtValues[0];
}

// Validate JWT signature using certificate
function validateJWTSignature(string jwtToken) returns jwt:Payload|error {
    jwt:ValidatorConfig validatorConfig = {
        issuer: jwtIssuer,
        clockSkew: clockSkew,
        signatureConfig: {
            certFile: certFilePath
        }
    };
    
    jwt:Payload|error result = jwt:validate(jwtToken, validatorConfig);
    
    if result is jwt:Payload {
        log:printInfo("JWT signature validated successfully");
        return result;
    } else {
        return error("JWT validation failed: " + result.message());
    }
}

// Extract userId from validated JWT payload
function extractUserIdFromJWT(jwt:Payload jwtPayload) returns string|error {
    // First try: userId claim
    if jwtPayload.hasKey("userId") {
        any|error userIdValue = jwtPayload.get("userId");
        if userIdValue is string {
            log:printInfo("Found userId claim in JWT: " + userIdValue);
            return userIdValue;
        } else if userIdValue is int|boolean {
            string userId = userIdValue.toString();
            log:printInfo("Found userId claim in JWT (converted to string): " + userId);
            return userId;
        }
    }
    
    // Second try: sub claim (standard JWT subject)
    if jwtPayload.hasKey("sub") {
        any|error subValue = jwtPayload.get("sub");
        if subValue is string {
            log:printInfo("Using sub claim as userId: " + subValue);
            return subValue;
        }
    }
    
    return error("Neither userId nor sub claim found in JWT payload");
}

// Extract issuer from access token claims (for metadata only)
function extractIssuer(RequestBody payload) returns string {
    Event? event = payload.event;
    if event is () {
        return "";
    }

    AccessToken? accessToken = event.accessToken;
    if accessToken is () {
        return "";
    }

    AccessTokenClaims[]? claims = accessToken.claims;
    if claims is () {
        return "";
    }

    foreach var claim in claims {
        if claim?.name == "iss" && claim?.value is string {
            string issuer = <string>claim.value;
            log:printInfo("Extracted issuer: " + issuer);
            return issuer;
        }
    }
    
    return "";
}

// Generate JWKS endpoint from issuer
function generateJWKSEndpoint(string issuer) returns string {
    if issuer == "" {
        return "N/A";
    }
    
    if issuer.endsWith("/token") {
        return issuer + "/jwks";
    }
    
    if issuer.endsWith("/oauth2") {
        return issuer + "/token/jwks";
    }
    
    return issuer + "/oauth2/token/jwks";
}

// Extract tenant name from organization or tenant object
function extractTenantName(RequestBody payload) returns string? {
    Event? event = payload.event;
    if event is () {
        return ();
    }
    
    // Try organization first
    Organization? org = event.organization;
    if org is Organization {
        string? name = org.name;
        if name is string {
            return name;
        }
    }
    
    // Fallback to tenant
    Tenant? tenant = event.tenant;
    if tenant is Tenant {
        string? name = tenant.name;
        if name is string {
            return name;
        }
    }
    
    return ();
}

// Extract grant type from request
function extractGrantType(RequestBody payload) returns string {
    Event? event = payload.event;
    if event is () {
        return "unknown";
    }

    Request? request = event.request;
    if request is () {
        return "unknown";
    }

    string? grantType = request.grantType;
    return grantType ?: "unknown";
}
