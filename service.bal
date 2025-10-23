import ballerina/http;
import ballerina/log;

configurable boolean enabledDebugLog = true;

// Extract userID from event payload
isolated function extractUserId(json payload) returns string|error {
    // Try to get userId from event.user.id (primary source)
    json eventJson = check payload.event;
    json userJson = check eventJson.user;
    json userIdJson = check userJson.id;
    
    if userIdJson is string {
        return userIdJson;
    }
    
    // Alternative: get from accessToken claims "sub" claim
    json? accessTokenJson = eventJson?.accessToken;
    if accessTokenJson is json {
        json? claimsJson = accessTokenJson?.claims;
        if claimsJson is json[] {
            foreach json claim in claimsJson {
                json? nameJson = claim?.name;
                json? valueJson = claim?.value;
                if nameJson == "sub" && valueJson is string {
                    return valueJson;
                }
            }
        }
    }
    
    return error("User ID not found in request payload");
}

// Response types
type SuccessResponseOk record {|
    *http:Ok;
    json body;
|};

type ErrorResponseBadRequest record {|
    *http:BadRequest;
    json body;
|};

type ErrorResponseInternalServerError record {|
    *http:InternalServerError;
    json body;
|};

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
    // This endpoint accepts requests without authentication for webhook calls
    isolated resource function post .(json payload, http:Request request) returns SuccessResponseOk|ErrorResponseBadRequest|ErrorResponseInternalServerError {
        do {
            if enabledDebugLog {
                log:printInfo(string `📥 Pre-Issue Access Token action triggered`);
                
                // Safely extract requestId and actionType
                json? requestIdJson = payload?.requestId;
                json? actionTypeJson = payload?.actionType;
                
                log:printInfo(string `Request ID: ${requestIdJson?.toString() ?: "unknown"}`);
                log:printInfo(string `Action Type: ${actionTypeJson?.toString() ?: "unknown"}`);
                
                // Log request headers for debugging
                string[] headerNames = request.getHeaderNames();
                foreach string headerName in headerNames {
                    string[]|http:HeaderNotFoundError headerValues = request.getHeaders(headerName);
                    if headerValues is string[] {
                        log:printInfo(string `Header ${headerName}: ${headerValues.toString()}`);
                    }
                }
            }
            
            // Validate action type
            json? actionTypeJson = payload?.actionType;
            if actionTypeJson != "PRE_ISSUE_ACCESS_TOKEN" {
                string msg = "Invalid action type";
                log:printError(string `${msg}: ${actionTypeJson?.toString() ?: "null"}`);
                return <ErrorResponseBadRequest>{
                    body: {
                        actionStatus: "ERROR",
                        errorMessage: msg,
                        errorDescription: "Support is available only for the PRE_ISSUE_ACCESS_TOKEN action type"
                    }
                };
            }
            
            // Extract userID from the payload
            string userId = check extractUserId(payload);
            
            if enabledDebugLog {
                log:printInfo(string `✅ Extracted userId: ${userId}`);
                
                // Safely extract debug info
                json? eventJson = payload?.event;
                json? userJson = eventJson?.user;
                json? userIdFromEventJson = userJson?.id;
                json? orgJson = eventJson?.organization;
                json? orgNameJson = orgJson?.name;
                json? tenantJson = eventJson?.tenant;
                json? tenantNameJson = tenantJson?.name;
                
                log:printInfo(string `👤 User from: ${userIdFromEventJson?.toString() ?: "N/A"}`);
                log:printInfo(string `🏢 Organization: ${orgNameJson?.toString() ?: "N/A"}`);
                log:printInfo(string `🏛️ Tenant: ${tenantNameJson?.toString() ?: "N/A"}`);
            }
            
            // Create the operation to add userId claim to access token
            json successResponse = {
                actionStatus: "SUCCESS",
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
            };
            
            if enabledDebugLog {
                log:printInfo(string `📤 Adding userId claim to access token`);
                log:printInfo(string `Response: ${successResponse.toJsonString()}`);
            }
            
            return <SuccessResponseOk>{
                body: successResponse
            };
            
        } on fail error err {
            string msg = "Something went wrong while processing Pre-Issue Access Token action";
            log:printError(string `💥 ${msg}: ${err.message()}`);
            
            return <ErrorResponseInternalServerError>{
                body: {
                    actionStatus: "ERROR",
                    errorMessage: msg,
                    errorDescription: err.message()
                }
            };
        }
    }
}
