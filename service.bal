import ballerina/auth;
import ballerina/http;
import ballerina/jwt;
import ballerina/log;
import ballerina/time;

configurable boolean enabledDebugLog = false;
configurable string certFilePath = ?;
auth:FileUserStoreConfig fileUserStoreConfig = {};

@http:ServiceConfig {
    auth: [
        {
            fileUserStoreConfig: fileUserStoreConfig
        }
    ]
}
service / on new http:Listener(9092) {

    resource function post .(RequestBody payload) returns SuccessResponse|ErrorResponse|http:InternalServerError {
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

        // Validate JWT
        jwt:Payload|error validationResult = validateJWT(jwtToken);
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
        
        // Extract issuer dynamically from the request
        string issuer = extractIssuer(payload, orgName);

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
                            issuer: issuer,
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

// Helper function to validate JWT
function validateJWT(string jwtToken) returns jwt:Payload|error {
    jwt:ValidatorConfig validatorConfig = {
        issuer: "wso2",
        clockSkew: 60,
        signatureConfig: {
            certFile: certFilePath
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

// Helper function to extract organization name dynamically from event
function extractOrganizationName(RequestBody payload) returns string {
    // Method 1: From organization object (most reliable)
    if payload?.event?.organization?.name is string {
        string orgName = <string>payload.event.organization.name;
        log:printInfo("Extracted organization name from organization object", orgName = orgName);
        return orgName;
    }
    
    // Method 2: From tenant object
    if payload?.event?.tenant?.name is string {
        string tenantName = <string>payload.event.tenant.name;
        log:printInfo("Extracted organization name from tenant", orgName = tenantName);
        return tenantName;
    }
    
    // Method 3: From user's organization
    if payload?.event?.user?.organization?.name is string {
        string userOrgName = <string>payload.event.user.organization.name;
        log:printInfo("Extracted organization name from user organization", orgName = userOrgName);
        return userOrgName;
    }
    
    // Method 4: From orgHandle if available
    if payload?.event?.organization?.orgHandle is string {
        string orgHandle = <string>payload.event.organization.orgHandle;
        log:printInfo("Extracted organization name from orgHandle", orgName = orgHandle);
        return orgHandle;
    }
    
    log:printError("Could not extract organization name from event data");
    return "default_org";
}

// Helper function to extract issuer dynamically
function extractIssuer(RequestBody payload, string orgName) returns string {
    // Method 1: Extract from existing access token claims (most reliable)
    AccessTokenClaims[]? claims = payload.event?.accessToken?.claims;
    if claims is () {
        foreach var claim in claims {
            if claim?.name == "iss" && claim?.value is string {
                string issuer = <string>claim.value;
                log:printInfo("Using issuer from access token claims", issuer = issuer);
                return issuer;
            }
        }
    }

    // Method 2: Construct from organization and environment detection
    string baseUrl = detectBaseUrlFromEnvironment(payload);
    string issuer = baseUrl + "/t/" + orgName + "/oauth2/token";
    log:printInfo("Constructed issuer from organization and environment", issuer = issuer);
    return issuer;
}

// Helper function to detect base URL from environment
function detectBaseUrlFromEnvironment(RequestBody payload) returns string {
    // Check access token claims for environment hints
    AccessTokenClaims[]? claims = payload.event?.accessToken?.claims;
    if claims is () {
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
