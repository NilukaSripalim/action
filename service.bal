import ballerina/http;
import ballerina/log;
import ballerina/time;

// Simple configuration for testing action trigger
configurable boolean enabledDebugLog = true;
configurable string testUserId = "testuser123";

// Simple function to extract JWT parameter (without validation)
function extractJWTFromParams(RequestParams[] reqParams) returns string|error {
    foreach RequestParams param in reqParams {
        string? name = param.name;
        string[]? value = param.value;
        
        if name == "jwt" && value is string[] && value.length() > 0 {
            string jwtToken = value[0];
            if jwtToken.trim() == "" {
                return error("JWT parameter is empty");
            }
            return jwtToken;
        }
    }
    
    return error("JWT parameter not found in request");
}

service /
on new http:Listener(9092) {

    // Health check endpoint
    resource function get health() returns json {
        return {
            status: "UP",
            service: "asgardeo-e2e-special-cases-simple",
            version: "1.0.0",
            timestamp: time:utcNow()[0],
            mode: "SIMPLE_ACTION_TRIGGER_TEST",
            testUserId: testUserId
        };
    }

    // Main webhook endpoint for Asgardeo Pre-Issue Access Token action
    // This version just handles the action trigger without JWT validation
    resource function post .(RequestBody payload) returns http:Ok|http:BadRequest {
        do {
            if enabledDebugLog {
                log:printInfo(string `📥 Received webhook request from Asgardeo`);
                log:printInfo(string `Request ID: ${payload.requestId ?: "unknown"}`);
                log:printInfo(string `Action Type: ${payload.actionType.toString()}`);
            }
            
            // Validate action type
            if payload.actionType != PRE_ISSUE_ACCESS_TOKEN {
                string msg = "Invalid action type";
                log:printError(string `${msg}: ${payload.actionType.toString()}`);
                return <http:BadRequest>{
                    body: {
                        actionStatus: "ERROR",
                        errorMessage: msg,
                        errorDescription: "Only PRE_ISSUE_ACCESS_TOKEN action type is supported"
                    }
                };
            }
            
            log:printInfo("✅ Action type validation passed: PRE_ISSUE_ACCESS_TOKEN");
            
            // Extract request parameters
            RequestParams[]? requestParams = payload.event?.request?.additionalParams;
            if requestParams is () {
                string msg = "Missing additional parameters";
                log:printError(msg);
                return <http:BadRequest>{
                    body: {
                        actionStatus: "ERROR",
                        errorMessage: msg,
                        errorDescription: "JWT parameter is required in additionalParams"
                    }
                };
            }
            
            log:printInfo("✅ Additional parameters found");
            
            // Extract JWT token (but don't validate it yet)
            string|error jwtResult = extractJWTFromParams(requestParams);
            
            if jwtResult is error {
                string msg = jwtResult.message();
                log:printError(string `❌ JWT extraction failed: ${msg}`);
                return <http:BadRequest>{
                    body: {
                        actionStatus: "ERROR",
                        errorMessage: "JWT parameter extraction failed",
                        errorDescription: msg
                    }
                };
            }
            
            string jwtToken = jwtResult;
            log:printInfo(string `✅ JWT token extracted (length: ${jwtToken.length()} characters)`);
            
            if enabledDebugLog {
                // Log first and last 20 characters for debugging
                string jwtPreview = jwtToken.length() > 40 ? 
                    jwtToken.substring(0, 20) + "..." + jwtToken.substring(jwtToken.length() - 20) :
                    "JWT_TOO_SHORT";
                log:printInfo(string `JWT Preview: ${jwtPreview}`);
            }
            
            // For now, just use the configured test userId
            // Later you can replace this with actual JWT validation
            string userId = testUserId;
            
            log:printInfo(string `✅ Using test userId: ${userId}`);
            
            // Return success response with userId claim
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
                log:printInfo(string `📤 Sending success response: ${successResponse.toJsonString()}`);
            }
            
            return <http:Ok>{
                body: successResponse
            };
            
        } on fail error err {
            string msg = "Internal server error during request processing";
            log:printError(string `💥 ${msg}: ${err.message()}`);
            
            return <http:BadRequest>{
                body: {
                    actionStatus: "ERROR",
                    errorMessage: msg,
                    errorDescription: err.message()
                }
            };
        }
    }

    // Test endpoint to simulate Asgardeo webhook call
    resource function post test() returns json {
        // Sample payload that mimics what Asgardeo sends
        RequestBody testPayload = {
            requestId: "test-" + time:utcNow()[0].toString(),
            actionType: PRE_ISSUE_ACCESS_TOKEN,
            event: {
                request: {
                    grantType: "client_credentials",
                    clientId: "DNrwSQcWhrfAImyLp0m_CjigT9Ma",
                    additionalParams: [
                        {
                            name: "jwt",
                            value: ["sample.jwt.token.for.testing"]
                        }
                    ]
                }
            }
        };
        
        log:printInfo("🧪 Test endpoint called - simulating Asgardeo webhook");
        
        return {
            status: "TEST_WEBHOOK_SIMULATION",
            message: "This endpoint simulates what Asgardeo would send",
            samplePayload: testPayload,
            instructions: [
                "1. Deploy this service to Choreo",
                "2. Get the webhook URL from Choreo",
                "3. Configure Pre-Issue Access Token action in Asgardeo",
                "4. Test with actual mobile app flow"
            ]
        };
    }
}
