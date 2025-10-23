import ballerina/http;
import ballerina/log;

configurable boolean enabledDebugLog = true;

// Extract userID from event payload
isolated function extractUserId(RequestBody payload) returns string|error {
    // Try to get userId from event.user.id (primary source)
    string? userId = payload.event?.user?.id;
    if userId is string {
        return userId;
    }
    
    // Alternative: get from accessToken claims "sub" claim
    AccessTokenClaims[]? claims = payload.event?.accessToken?.claims;
    if claims is AccessTokenClaims[] {
        foreach AccessTokenClaims claim in claims {
            if claim.name == "sub" && claim.value is string {
                return claim.value;
            }
        }
    }
    
    return error("User ID not found in request payload");
}

@http:ServiceConfig {
    cors: {
        allowCredentials: false,
        allowOrigins: ["*"],
        allowMethods: ["GET", "POST", "OPTIONS"],
        allowHeaders: ["*"]
    }
}
isolated service / on new http:Listener(9092) {

    // Health check endpoint (publicly accessible)
    isolated resource function get health() returns json {
        return {
            status: "UP",
            service: "asgardeo-e2e-special-cases",
            version: "1.0.0",
            description: "Pre-Issue Access Token Action - UserID Injection"
        };
    }

    // Main webhook endpoint for Asgardeo Pre-Issue Access Token action
    isolated resource function post .(RequestBody payload) returns SuccessResponseOk|ErrorResponseBadRequest|ErrorResponseInternalServerError|error {
        do {
            if enabledDebugLog {
                log:printInfo("📥 Pre-Issue Access Token action triggered");
                log:printInfo(string `Request ID: ${payload.requestId ?: "unknown"}`);
                log:printInfo(string `Action Type: ${payload.actionType.toString()}`);
            }
            
            // Validate action type
            if payload.actionType == PRE_ISSUE_ACCESS_TOKEN {
                // Extract userID from the payload
                string userId = check extractUserId(payload);
                
                if enabledDebugLog {
                    log:printInfo(string `✅ Extracted userId: ${userId}`);
                    log:printInfo(string `👤 User from: ${payload.event?.user?.id ?: "N/A"}`);
                    log:printInfo(string `🏢 Organization: ${payload.event?.organization?.name ?: "N/A"}`);
                    log:printInfo(string `🏛️ Tenant: ${payload.event?.tenant?.name ?: "N/A"}`);
                }
                
                // Return success response with userId claim
                return <SuccessResponseOk>{
                    body: <SuccessResponse>{
                        actionStatus: SUCCESS,
                        operations: [
                            {
                                op: "add",
                                path: "/accessToken/claims/-",
                                value: {
                                    name: "userId",
                                    value: userId
                                }
                            }
                        ]
                    }
                };
            }
            
            return <ErrorResponseBadRequest>{
                body: {
                    actionStatus: ERROR,
                    errorMessage: "Invalid action type",
                    errorDescription: "Support is available only for the PRE_ISSUE_ACCESS_TOKEN action type"
                }
            };
            
        } on fail error err {
            string msg = "Something went wrong while processing Pre-Issue Access Token action";
            if enabledDebugLog {
                log:printError(string `💥 ${msg}: ${err.message()}`);
            }
            
            return <ErrorResponseInternalServerError>{
                body: {
                    actionStatus: ERROR,
                    errorMessage: msg,
                    errorDescription: err.message()
                }
            };
        }
    }
}
