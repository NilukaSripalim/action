import ballerina/http;
import ballerina/log;
import ballerina/time;
import ballerina/jwt;

service / on new http:Listener(9090) {

    resource function post actionchoreomfavalidation(@http:Payload RequestBody payload) returns SuccessResponse|ErrorResponse {
        log:printInfo("Received pre-issue access token action request");
        
        // Extract issuer from access token claims (WSO2 has already validated this request)
        string issuer = extractIssuer(payload);
        
        if issuer == "" {
            log:printError("Failed to extract issuer from payload");
            ErrorResponse errorResp = {
                actionStatus: "FAILED",
                failureReason: "invalid_request",
                failureDescription: "Missing issuer claim in access token"
            };
            return errorResp;
        }
        
        // Generate JWKS endpoint for reference (will be used when token is actually validated)
        string jwksEndpoint = generateJWKSEndpoint(issuer);
        
        // Extract user ID
        string userId = extractUserId(payload);
        
        string timestamp = time:utcToString(time:utcNow());

        log:printInfo(string `Processing pre-issue request - User: ${userId}, Issuer: ${issuer}`);

        // Create operations to modify the access token
        Operations[] operations = [];

        // Add userId claim
        Operations userIdOp = {
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "userId",
                value: userId
            }
        };
        operations.push(userIdOp);

        // Add validation metadata (for reference, actual validation happens post-issue)
        string validationMetadata = string `{"requestValidated":"true","issuer":"${issuer}","jwksEndpoint":"${jwksEndpoint}","timestamp":"${timestamp}","note":"Token signature will be validated by resource server using JWKS endpoint"}`;
        Operations validationOp = {
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "validationMetadata",
                value: validationMetadata
            }
        };
        operations.push(validationOp);

        // Add organization/tenant metadata
        string? tenantName = extractTenantName(payload);
        if tenantName is string {
            Operations tenantOp = {
                op: "add",
                path: "/accessToken/claims/-",
                value: {
                    name: "tenantName",
                    value: tenantName
                }
            };
            operations.push(tenantOp);
        }

        // Add grant type for auditing
        string grantType = extractGrantType(payload);
        Operations grantOp = {
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "grantType",
                value: grantType
            }
        };
        operations.push(grantOp);

        SuccessResponse response = {
            actionStatus: "SUCCESS",
            operations: operations
        };
        
        log:printInfo("Successfully processed pre-issue action for user: " + userId);
        return response;
    }
}

// Extract user ID from the request
function extractUserId(RequestBody payload) returns string {
    if payload.event is () {
        return "unknown-user";
    }

    Event event = <Event>payload.event;
    
    // Method 1: From user object (most reliable)
    if event.user is User {
        User user = <User>event.user;
        if user?.id is string {
            string userId = <string>user.id;
            log:printInfo("Found user ID from user object: " + userId);
            return userId;
        }
    }
    
    // Method 2: From access token sub claim
    if event.accessToken is AccessToken {
        AccessToken accessToken = <AccessToken>event.accessToken;
        if accessToken?.claims is AccessTokenClaims[] {
            AccessTokenClaims[] claims = <AccessTokenClaims[]>accessToken.claims;
            foreach var claim in claims {
                if claim?.name == "sub" && claim?.value is string {
                    string userId = <string>claim.value;
                    log:printInfo("Found user ID from sub claim: " + userId);
                    return userId;
                }
            }
        }
    }
    
    log:printWarn("Could not extract user ID");
    return "unknown-user";
}

// Extract issuer from access token claims
function extractIssuer(RequestBody payload) returns string {
    if payload.event is () {
        log:printError("No event in payload");
        return "";
    }

    Event event = <Event>payload.event;
    
    if event.accessToken is AccessToken {
        AccessToken accessToken = <AccessToken>event.accessToken;
        if accessToken?.claims is AccessTokenClaims[] {
            AccessTokenClaims[] claims = <AccessTokenClaims[]>accessToken.claims;
            foreach var claim in claims {
                if claim?.name == "iss" && claim?.value is string {
                    string issuer = <string>claim.value;
                    log:printInfo("Extracted issuer: " + issuer);
                    return issuer;
                }
            }
        }
    }
    
    log:printError("Could not extract issuer from access token claims");
    return "";
}

// Generate JWKS endpoint from issuer
function generateJWKSEndpoint(string issuer) returns string {
    if issuer.endsWith("/token") {
        return issuer + "/jwks";
    }
    
    if issuer.endsWith("/oauth2") {
        return issuer + "/token/jwks";
    }
    
    // Default pattern
    return issuer + "/oauth2/token/jwks";
}

// Extract tenant name
function extractTenantName(RequestBody payload) returns string? {
    if payload.event is () {
        return ();
    }

    Event event = <Event>payload.event;
    
    if event.organization is Organization {
        Organization org = <Organization>event.organization;
        if org?.name is string {
            return <string>org.name;
        }
    }
    
    if event.tenant is Tenant {
        Tenant tenant = <Tenant>event.tenant;
        if tenant?.name is string {
            return <string>tenant.name;
        }
    }
    
    return ();
}

// Extract grant type
function extractGrantType(RequestBody payload) returns string {
    if payload.event is () {
        return "unknown";
    }

    Event event = <Event>payload.event;
    
    if event.request is Request {
        Request request = <Request>event.request;
        if request?.grantType is string {
            return <string>request.grantType;
        }
    }
    
    return "unknown";
}
