import ballerina/http;
import ballerina/jwt;
import ballerina/log;

configurable boolean enabledDebugLog = true;

// For HS256 testing - use a shared secret
configurable string TEST_JWT_SECRET = "your-test-secret-key-here";

// Extract JWT from additionalParams and validate signature
function extractAndValidateJWT(RequestBody payload) returns string|error {
    // 1. Extract JWT from additionalParams
    RequestParams[]? requestParams = payload.event?.request?.additionalParams;
    if requestParams is () {
        return error("JWT parameter missing in additionalParams");
    }
    
    // 2. Extract JWT string from parameters
    string jwtToken = check extractJWT(requestParams);
    
    if enabledDebugLog {
        log:printInfo(string `🔐 Extracted JWT token: ${jwtToken}`);
    }
    
    // 3. First, decode header to detect algorithm
    [jwt:Header, jwt:Payload] [jwtHeader, _] = check jwt:decode(jwtToken);
    
    string? algorithm = jwtHeader.alg;
    if enabledDebugLog {
        log:printInfo(string `🔐 Detected JWT Algorithm: ${algorithm.toString()}`);
    }
    
    // 4. Validate based on algorithm - For testing, we'll use HS256 with shared secret
    jwt:Payload|error validationResult;
    
    if algorithm == "HS256" {
        if enabledDebugLog {
            log:printInfo("🔄 Using HS256 validation with shared secret");
        }
        jwt:ValidatorConfig validatorConfig = {
            issuer: "wso2",
            clockSkew: 60,
            signatureConfig: {
                secret: TEST_JWT_SECRET
            }
        };
        validationResult = jwt:validate(jwtToken, validatorConfig);
    } else {
        return error("Unsupported JWT algorithm: " + algorithm.toString());
    }
    
    if validationResult is error {
        return error("JWT signature validation failed: " + validationResult.message());
    }
    
    if enabledDebugLog {
        log:printInfo("✅ JWT signature validation successful");
    }
    
    return jwtToken;
}

// Extract userID from validated JWT payload
function extractUserIdFromValidatedJWT(string jwtToken) returns string|error {
    // Decode the validated JWT to get payload
    [jwt:Header, jwt:Payload] [_, jwtPayload] = check jwt:decode(jwtToken);
    
    if enabledDebugLog {
        log:printInfo(string `📋 JWT Payload: ${jwtPayload.toJsonString()}`);
    }
    
    // Try to get userId from JWT claims - using "userId" claim (matches your test JWT)
    anydata? userIdClaim = jwtPayload.get("userId");
    if userIdClaim is string {
        return userIdClaim;
    }
    
    // Alternative: use "sub" claim if userId not present
    anydata? subClaim = jwtPayload.get("sub");
    if subClaim is string {
        return subClaim;
    }
    
    return error("User ID not found in validated JWT claims");
}

// Extract JWT from request parameters
function extractJWT(RequestParams[] reqParams) returns string|error {
    map<string> params = {};
    foreach RequestParams param in reqParams {
        string[]? value = param.value;
        string? name = param.name;
        if name is string && value is string[] && value.length() > 0 {
            params[name] = value[0];
        }
    }
    
    string? jwt = params["jwt"];
    if jwt is string {
        return jwt;
    }
    
    return error("JWT parameter not found in request parameters");
}

@http:ServiceConfig {
    cors: {
        allowCredentials: false,
        allowOrigins: ["*"],
        allowMethods: ["GET", "POST", "OPTIONS"],
        allowHeaders: ["*"]
    }
}
service /action on new http:Listener(9092) {

    // Health check endpoint
    resource function get health() returns json {
        return {
            status: "UP",
            serviceName: "asgardeo-pre-issue-action",
            version: "1.0.0",
            description: "Pre-Issue Access Token Action - JWT Validated UserID Injection"
        };
    }

    // Main webhook endpoint for Asgardeo Pre-Issue Access Token action
    resource function post .(RequestBody payload) returns http:Response|error {
        if enabledDebugLog {
            log:printInfo("📥 Pre-Issue Access Token action triggered");
            log:printInfo(string `Request ID: ${payload.requestId ?: "unknown"}`);
            log:printInfo(string `Action Type: ${payload.actionType.toString()}`);
            log:printInfo(string `Grant Type: ${payload.event?.request?.grantType ?: "unknown"}`);
        }
        
        // Validate action type
        if payload.actionType != PRE_ISSUE_ACCESS_TOKEN {
            return {
                statusCode: 400,
                body: {
                    actionStatus: ERROR,
                    errorMessage: "Invalid action type",
                    errorDescription: "Support is available only for the PRE_ISSUE_ACCESS_TOKEN action type"
                }
            };
        }
        
        // Validate JWT signature and extract userId
        string|error validatedJWT = extractAndValidateJWT(payload);
        if validatedJWT is error {
            return {
                statusCode: 400,
                body: {
                    actionStatus: FAILED,
                    failureReason: "invalid_token",
                    failureDescription: validatedJWT.message()
                }
            };
        }
        
        string|error userId = extractUserIdFromValidatedJWT(validatedJWT);
        if userId is error {
            return {
                statusCode: 400,
                body: {
                    actionStatus: FAILED,
                    failureReason: "invalid_token",
                    failureDescription: userId.message()
                }
            };
        }
        
        if enabledDebugLog {
            log:printInfo(string `✅ Extracted userId from validated JWT: ${userId}`);
            log:printInfo("🔐 JWT Signature Validated: YES");
        }
        
        // Return success response with userId claim
        return {
            statusCode: 200,
            body: {
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
}
