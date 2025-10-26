import ballerina/http;
import ballerina/jwt;

configurable boolean enabledDebugLog = true;

// Make issuer configurable
configurable string JWT_ISSUER = "https://api.asgardeo.io/t/orgasgardeouse2e/oauth2/token";

// JWKS endpoint for Asgardeo
configurable string JWKS_ENDPOINT = "https://api.asgardeo.io/t/orgasgardeouse2e/oauth2/jwks";

// Extract JWT from additionalParams and validate signature with JWKS
function extractAndValidateJWT(RequestBody payload) returns string|error {
    // 1. Extract JWT from additionalParams
    RequestParams[]? requestParams = payload.event?.request?.additionalParams;
    if requestParams is () {
        return error("JWT parameter missing in additionalParams");
    }
    
    // 2. Extract JWT string from parameters
    string jwtToken = check extractJWT(requestParams);
    
    // 3. Use JWKS validation for Asgardeo tokens
    jwt:ValidatorConfig validatorConfig = {
        issuer: JWT_ISSUER,
        clockSkew: 60,
        signatureConfig: {
            jwksConfig: {
                url: JWKS_ENDPOINT
            }
        }
    };
    
    jwt:Payload|error validationResult = jwt:validate(jwtToken, validatorConfig);
    
    if validationResult is error {
        return error("JWT signature validation failed: " + validationResult.message());
    }
    
    return jwtToken;
}

// Extract userID from validated JWT payload
function extractUserIdFromValidatedJWT(string jwtToken) returns string|error {
    // Decode the validated JWT to get payload
    [jwt:Header, jwt:Payload] [_, jwtPayload] = check jwt:decode(jwtToken);
    
    // Try to get userId from JWT claims - using 'sub' claim for Asgardeo
    anydata? subClaim = jwtPayload.get("sub");
    if subClaim is string {
        return subClaim;
    }
    
    // Alternative: check for other user identifiers
    anydata? userIdClaim = jwtPayload.get("userId");
    if userIdClaim is string {
        return userIdClaim;
    }
    
    // Try username claim
    anydata? usernameClaim = jwtPayload.get("username");
    if usernameClaim is string {
        return usernameClaim;
    }
    
    // Try email claim
    anydata? emailClaim = jwtPayload.get("email");
    if emailClaim is string {
        return emailClaim;
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
    resource function post .(RequestBody payload) returns json|error {
        // Validate action type
        if payload.actionType != PRE_ISSUE_ACCESS_TOKEN {
            return {
                actionStatus: ERROR,
                errorMessage: "Invalid action type",
                errorDescription: "Support is available only for the PRE_ISSUE_ACCESS_TOKEN action type"
            };
        }
        
        // Validate JWT signature and extract userId
        string|error validatedJWT = extractAndValidateJWT(payload);
        if validatedJWT is error {
            return {
                actionStatus: FAILED,
                failureReason: "invalid_token",
                failureDescription: validatedJWT.message()
            };
        }
        
        string|error userId = extractUserIdFromValidatedJWT(validatedJWT);
        if userId is error {
            return {
                actionStatus: FAILED,
                failureReason: "invalid_token",
                failureDescription: userId.message()
            };
        }
        
        // Return success response with userId claim
        return {
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
        };
    }
}
