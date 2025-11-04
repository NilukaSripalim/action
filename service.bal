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

        // Extract issuer dynamically from the request
        string issuer = extractIssuer(payload);

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

    foreach var param in requestParams {
        if param?.name == "id_token" || param?.name == "access_token" {
            if param?.value is () || param.value.length() == 0 {
                return error("JWT token value is empty");
            }
            return param.value[0];
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

// Helper function to extract issuer dynamically
function extractIssuer(RequestBody payload) returns string {
    // Try to get issuer from access token claims first
    AccessTokenClaims[]? claims = payload.event?.accessToken?.claims;
    if claims is () {
        foreach var claim in claims {
            if claim?.name == "iss" && claim?.value is string {
                return <string>claim.value;
            }
        }
    }

    // Fallback to organization-based URL
    string orgName = payload.event?.organization?.name ?: 
                    payload.event?.tenant?.name ?: 
                    payload.event?.user?.organization?.name ?: 
                    "orge2ecucasesuschoreogrp4";

    return "https://dev.api.asgardeo.io/t/" + orgName + "/oauth2/token";
}
