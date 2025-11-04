import ballerina/auth;
import ballerina/http;
import ballerina/jwt;
import ballerina/log;
import ballerina/time;

configurable boolean enabledDebugLog = false;
auth:FileUserStoreConfig fileUserStoreConfig = {};

@http:ServiceConfig {
    auth: [
        {
            fileUserStoreConfig: fileUserStoreConfig
        }
    ]
}
service / on new http:Listener(9092) {

    resource function post 'choreo-mfa-validation(@http:Payload RequestBody payload) returns SuccessResponse|ErrorResponse|http:InternalServerError {
        if enabledDebugLog {
            log:printDebug("Received payload: " + payload.toJsonString());
        }

        // Validate action type
        if payload.actionType != PRE_ISSUE_ACCESS_TOKEN {
            ErrorResponse errorResp = {
                actionStatus: ERROR,
                errorMessage: "Invalid action type",
                errorDescription: "Support is available only for the PRE_ISSUE_ACCESS_TOKEN action type"
            };
            log:printError("Invalid action type received: " + payload.actionType.toString());
            return errorResp;
        }

        // Extract and validate JWT
        string|error jwtResult = extractJWT(payload);
        if jwtResult is error {
            ErrorResponse errorResp = {
                actionStatus: ERROR,
                errorMessage: "JWT extraction failed",
                errorDescription: jwtResult.message()
            };
            log:printError("JWT extraction failed: " + jwtResult.message());
            return errorResp;
        }
        string jwtToken = jwtResult;

        // Extract issuer from event to get JWKS endpoint
        string issuer = extractIssuerForValidation(payload);
        string jwksEndpoint = issuer + "/jwks"; // Standard JWKS endpoint

        // Validate JWT with dynamic JWKS
        jwt:Payload|error validationResult = validateJWTWithJWKS(jwtToken, jwksEndpoint);
        if validationResult is error {
            ErrorResponse errorResp = {
                actionStatus: ERROR,
                errorMessage: "JWT validation failed",
                errorDescription: validationResult.message()
            };
            log:printError("JWT validation failed: " + validationResult.message());
            return errorResp;
        }
        jwt:Payload jwtPayload = validationResult;

        // Extract userId from JWT payload
        string|error userIdResult = extractUserIdFromJWT(jwtPayload);
        if userIdResult is error {
            ErrorResponse errorResp = {
                actionStatus: ERROR,
                errorMessage: "User ID extraction failed",
                errorDescription: userIdResult.message()
            };
            log:printError("User ID extraction failed: " + userIdResult.message());
            return errorResp;
        }
        string userId = userIdResult;

        // Extract organization name dynamically
        string orgName = extractOrganizationName(payload);
        
        // Extract issuer for the response (might be different from validation issuer)
        string responseIssuer = extractIssuer(payload, orgName);

        string timestamp = time:utcToString(time:utcNow());

        // Create success response with all required operations
        SuccessResponse successResp = {
            actionStatus: SUCCESS,
            operations: [
                {
                    op: "add",
                    path: "/accessToken/claims/-",
                    value: {
                        name: "userId",
                        value: userId
                    }
                },
                {
                    op: "add",
                    path: "/accessToken/claims/-",
                    value: {
                        name: "tokenValidation",
                        value: {
                            signature: "valid",
                            method: "JWKS_RS256",
                            issuer: responseIssuer,
                            timestamp: timestamp
                        }
                    }
                },
                {
                    op: "add",
                    path: "/accessToken/claims/-",
                    value: {
                        name: "mfaValidation",
                        value: {
                            status: "success",
                            method: "ID_TOKEN_AMR_VALIDATION",
                            timestamp: timestamp
                        }
                    }
                }
            ]
        };

        if enabledDebugLog {
            log:printDebug("Success response: " + successResp.toJsonString());
        }

        return successResp;
    }
}

// Helper function to extract JWT from request parameters
function extractJWT(RequestBody payload) returns string|error {
    RequestParams[]? requestParams = payload.event?.request?.additionalParams;
    
    if requestParams is () {
        return error("Required parameters for JWT validation are missing");
    }

    RequestParams[] paramsArray = <RequestParams[]>requestParams;
    foreach RequestParams param in paramsArray {
        if param?.name == "id_token" || param?.name == "access_token" {
            if param?.value is () {
                return error("JWT token value is empty");
            }
            string[] valueArray = <string[]>param.value;
            if valueArray.length() == 0 {
                return error("JWT token value is empty");
            }
            return valueArray[0];
        }
    }

    return error("JWT token not found in additional parameters");
}

// Helper function to validate JWT with dynamic JWKS
function validateJWTWithJWKS(string jwtToken, string jwksEndpoint) returns jwt:Payload|error {
    jwt:ValidatorConfig validatorConfig = {
        issuer: "wso2",
        clockSkew: 60,
        signatureConfig: {
            jwksConfig: {
                url: jwksEndpoint
            }
        }
    };

    return jwt:validate(jwtToken, validatorConfig);
}

// Helper function to extract userId from JWT payload
function extractUserIdFromJWT(jwt:Payload jwtPayload) returns string|error {
    anydata userIdValue = jwtPayload.get("userId");
    
    if userIdValue is () {
        return error("userId claim not found in JWT payload");
    }

    if userIdValue is string {
        return userIdValue;
    }

    return userIdValue.toString();
}

// Helper function to extract issuer for JWT validation (from access token claims)
function extractIssuerForValidation(RequestBody payload) returns string {
    // Check if event exists
    if payload.event is () {
        log:printError("Event is missing from payload");
        return "https://api.asgardeo.io/t/default_org/oauth2/token";
    }

    Event event = <Event>payload.event;

    // Extract from existing access token claims (most reliable)
    AccessToken? accessToken = event.accessToken;
    if accessToken is AccessToken && accessToken?.claims is () {
        AccessTokenClaims[] claims = <AccessTokenClaims[]>accessToken.claims;
        foreach var claim in claims {
            if claim?.name == "iss" && claim?.value is string {
                string issuer = <string>claim.value;
                log:printInfo("Using issuer from access token claims for validation", issuer = issuer);
                return issuer;
            }
        }
    }

    // Fallback: Construct from organization
    string orgName = extractOrganizationName(payload);
    string baseUrl = detectBaseUrlFromEnvironment(payload);
    string issuer = baseUrl + "/t/" + orgName + "/oauth2/token";
    log:printInfo("Constructed issuer for validation", issuer = issuer);
    return issuer;
}

// Helper function to extract organization name dynamically from event
function extractOrganizationName(RequestBody payload) returns string {
    // Check if event exists
    if payload.event is () {
        log:printError("Event is missing from payload");
        return "default_org";
    }

    Event event = <Event>payload.event;

    // Method 1: From organization object (most reliable)
    Organization? organization = event.organization;
    if organization is Organization && organization?.name is string {
        string orgName = <string>organization.name;
        log:printInfo("Extracted organization name from organization object", orgName = orgName);
        return orgName;
    }
    
    // Method 2: From tenant object
    Tenant? tenant = event.tenant;
    if tenant is Tenant && tenant?.name is string {
        string tenantName = <string>tenant.name;
        log:printInfo("Extracted organization name from tenant", orgName = tenantName);
        return tenantName;
    }
    
    // Method 3: From user's organization
    User? user = event.user;
    if user is User {
        Organization? userOrg = user.organization;
        if userOrg is Organization && userOrg?.name is string {
            string userOrgName = <string>userOrg.name;
            log:printInfo("Extracted organization name from user organization", orgName = userOrgName);
            return userOrgName;
        }
    }
    
    // Method 4: From orgHandle if available
    if organization is Organization && organization?.orgHandle is string {
        string orgHandle = <string>organization.orgHandle;
        log:printInfo("Extracted organization name from orgHandle", orgName = orgHandle);
        return orgHandle;
    }
    
    log:printError("Could not extract organization name from event data");
    return "default_org";
}

// Helper function to extract issuer for response
function extractIssuer(RequestBody payload, string orgName) returns string {
    // Check if event exists
    if payload.event is () {
        log:printError("Event is missing from payload");
        return "https://api.asgardeo.io/t/" + orgName + "/oauth2/token";
    }

    Event event = <Event>payload.event;

    // Method 1: Extract from existing access token claims (most reliable)
    AccessToken? accessToken = event.accessToken;
    if accessToken is AccessToken && accessToken?.claims is () {
        AccessTokenClaims[] claims = <AccessTokenClaims[]>accessToken.claims;
        foreach var claim in claims {
            if claim?.name == "iss" && claim?.value is string {
                string issuer = <string>claim.value;
                log:printInfo("Using issuer from access token claims for response", issuer = issuer);
                return issuer;
            }
        }
    }

    // Method 2: Construct from organization and environment detection
    string baseUrl = detectBaseUrlFromEnvironment(payload);
    string issuer = baseUrl + "/t/" + orgName + "/oauth2/token";
    log:printInfo("Constructed issuer for response", issuer = issuer);
    return issuer;
}

// Helper function to detect base URL from environment
function detectBaseUrlFromEnvironment(RequestBody payload) returns string {
    // Check if event exists
    if payload.event is () {
        return "https://api.asgardeo.io";
    }

    Event event = <Event>payload.event;

    // Check access token claims for environment hints
    AccessToken? accessToken = event.accessToken;
    if accessToken is AccessToken && accessToken?.claims is () {
        AccessTokenClaims[] claims = <AccessTokenClaims[]>accessToken.claims;
        foreach var claim in claims {
            if claim?.name == "iss" && claim?.value is string {
                string issuer = <string>claim.value;
                if issuer.includes("dev.api.asgardeo.io") {
                    return "https://dev.api.asgardeo.io";
                } else if issuer.includes("stage.api.asgardeo.io") {
                    return "https://stage.api.asgardeo.io";
                } else if issuer.includes("api.asgardeo.io") && !issuer.includes("dev.") && !issuer.includes("stage.") {
                    return "https://api.asgardeo.io";
                } else if issuer.includes("localhost") {
                    return "https://localhost:9443";
                }
            }
        }
    }

    // Default to production environment
    return "https://api.asgardeo.io";
}
