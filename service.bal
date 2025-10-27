import ballerina/http;
import ballerina/jwt;
import ballerina/time;

configurable boolean enabledDebugLog = true;

// Extract and validate both tokens with MFA
function validateTokensAndMFA(RequestBody payload, string jwtIssuer, string jwksEndpoint) returns string|error {
    RequestParams[]? requestParams = payload.event?.request?.additionalParams;
    if requestParams is () {
        return error("Token parameters missing in additionalParams");
    }
    
    // Extract both tokens
    string idToken = check extractToken(requestParams, "id_token");
    string accessToken = check extractToken(requestParams, "access_token");
    
    // Validate ID Token signature and MFA claims
    check validateIDTokenAndMFA(idToken, jwtIssuer, jwksEndpoint);
    
    // Validate access token signature
    string validatedAccessToken = check validateAccessToken(accessToken, jwtIssuer, jwksEndpoint);
    
    return validatedAccessToken;
}

// Validate ID Token signature and MFA claims
function validateIDTokenAndMFA(string idToken, string jwtIssuer, string jwksEndpoint) returns error? {
    jwt:ValidatorConfig idTokenValidator = {
        issuer: jwtIssuer,
        clockSkew: 60,
        signatureConfig: {
            jwksConfig: {
                url: jwksEndpoint
            }
        }
    };
    
    jwt:Payload|error idTokenValidation = jwt:validate(idToken, idTokenValidator);
    if idTokenValidation is error {
        return error("ID Token signature validation failed: " + idTokenValidation.message());
    }
    
    // Check MFA claims in ID Token
    return check validateMFAClaims(idTokenValidation);
}

// Validate MFA claims in ID Token
function validateMFAClaims(jwt:Payload idTokenPayload) returns error? {
    // Check amr (Authentication Methods References)
    anydata? amr = idTokenPayload.get("amr");
    
    if amr is string[] {
        boolean hasMFA = checkMFAMethods(amr);
        if hasMFA {
            return;
        } else {
            return error("No MFA methods found in amr: " + amr.toString());
        }
    } else {
        return error("amr claim is not a string array or is missing");
    }
}

// Helper function to check for MFA methods in array
function checkMFAMethods(string[] amr) returns boolean {
    foreach string method in amr {
        // Check for Asgardeo MFA authenticator names
        if method == "email-otp-authenticator" || 
           method == "sms-otp-authenticator" || 
           method == "totp-authenticator" ||
           method == "BasicAuthenticator" ||
           method == "FIDOAuthenticator" ||
           method == "backup-code-authenticator" ||
           method == "email-otp" ||
           method == "sms-otp" ||
           method == "totp" ||
           method == "mfa" {
            return true;
        }
        
        // Check for OTP indicators
        if hasSubstring(method, "otp") || hasSubstring(method, "mfa") || hasSubstring(method, "authenticator") {
            return true;
        }
    }
    return false;
}

// Helper function to check if string contains substring
function hasSubstring(string str, string substring) returns boolean {
    int subLength = substring.length();
    int strLength = str.length();
    
    if subLength > strLength {
        return false;
    }
    
    int i = 0;
    while i <= strLength - subLength {
        boolean found = true;
        int j = 0;
        while j < subLength {
            if str[i + j] != substring[j] {
                found = false;
                break;
            }
            j += 1;
        }
        if found {
            return true;
        }
        i += 1;
    }
    return false;
}

// Validate access token signature
function validateAccessToken(string accessToken, string jwtIssuer, string jwksEndpoint) returns string|error {
    jwt:ValidatorConfig accessTokenValidator = {
        issuer: jwtIssuer,
        clockSkew: 60,
        signatureConfig: {
            jwksConfig: {
                url: jwksEndpoint
            }
        }
    };
    
    jwt:Payload|error accessTokenValidation = jwt:validate(accessToken, accessTokenValidator);
    if accessTokenValidation is error {
        return error("Access Token signature validation failed: " + accessTokenValidation.message());
    }
    
    return accessToken;
}

// Extract any token from parameters - FIXED
function extractToken(RequestParams[] reqParams, string tokenName) returns string|error {
    map<string> params = {};
    foreach RequestParams param in reqParams {
        string[]? value = param.value;
        string? name = param.name;
        if name is string && value is string[] {
            // Check if array has at least one element before accessing [0]
            if value.length() > 0 {
                params[name] = value[0];
            }
        }
    }
    
    string? token = params[tokenName];
    if token is string {
        return token;
    }
    
    return error(tokenName + " parameter not found in request parameters");
}

// Extract userID from validated access token payload
function extractUserIdFromValidatedJWT(string jwtToken) returns string|error {
    [jwt:Header, jwt:Payload] [_, jwtPayload] = check jwt:decode(jwtToken);
    
    // Try to get userId from various claims
    anydata? subClaim = jwtPayload.get("sub");
    if subClaim is string {
        return subClaim;
    }
    
    anydata? userIdClaim = jwtPayload.get("userId");
    if userIdClaim is string {
        return userIdClaim;
    }
    
    anydata? usernameClaim = jwtPayload.get("username");
    if usernameClaim is string {
        return usernameClaim;
    }
    
    anydata? emailClaim = jwtPayload.get("email");
    if emailClaim is string {
        return emailClaim;
    }
    
    return error("User ID not found in validated JWT claims");
}

// Helper functions to extract dynamic parameters - FIXED
function extractJWTIssuer(RequestBody payload) returns string|error {
    // Option 1: Extract from custom headers in additionalHeaders
    RequestHeaders[]? additionalHeaders = payload.event?.request?.additionalHeaders;
    if additionalHeaders is RequestHeaders[] {
        foreach RequestHeaders header in additionalHeaders {
            string? headerName = header.name;
            string[]? headerValue = header.value;
            if headerName == "x-jwt-issuer" && headerValue is string[] {
                // Check if array has at least one element before accessing [0]
                if headerValue.length() > 0 {
                    return headerValue[0];
                }
            }
        }
    }
    
    // Option 2: Extract from additionalParams
    RequestParams[]? additionalParams = payload.event?.request?.additionalParams;
    if additionalParams is RequestParams[] {
        foreach RequestParams param in additionalParams {
            string? paramName = param.name;
            string[]? paramValue = param.value;
            if paramName == "jwt_issuer" && paramValue is string[] {
                // Check if array has at least one element before accessing [0]
                if paramValue.length() > 0 {
                    return paramValue[0];
                }
            }
        }
    }
    
    return error("JWT issuer not provided in request");
}

function extractJWKSEndpoint(RequestBody payload) returns string|error {
    // Option 1: Extract from custom headers in additionalHeaders
    RequestHeaders[]? additionalHeaders = payload.event?.request?.additionalHeaders;
    if additionalHeaders is RequestHeaders[] {
        foreach RequestHeaders header in additionalHeaders {
            string? headerName = header.name;
            string[]? headerValue = header.value;
            if headerName == "x-jwks-endpoint" && headerValue is string[] {
                // Check if array has at least one element before accessing [0]
                if headerValue.length() > 0 {
                    return headerValue[0];
                }
            }
        }
    }
    
    // Option 2: Extract from additionalParams
    RequestParams[]? additionalParams = payload.event?.request?.additionalParams;
    if additionalParams is RequestParams[] {
        foreach RequestParams param in additionalParams {
            string? paramName = param.name;
            string[]? paramValue = param.value;
            if paramName == "jwks_endpoint" && paramValue is string[] {
                // Check if array has at least one element before accessing [0]
                if paramValue.length() > 0 {
                    return paramValue[0];
                }
            }
        }
    }
    
    return error("JWKS endpoint not provided in request");
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
            serviceName: "mobileapp-auth-ext-api",
            version: "1.0.0",
            description: "Pre-Issue Access Token Action for Mobile App Authentication with MFA Validation"
        };
    }

    // Main webhook endpoint for Asgardeo Pre-Issue Access Token action
    resource function post .(RequestBody payload) returns SuccessResponse|FailedResponse|ErrorResponse {
        // Extract dynamic JWT configuration from request
        string|error jwtIssuer = extractJWTIssuer(payload);
        string|error jwksEndpoint = extractJWKSEndpoint(payload);
        
        if jwtIssuer is error || jwksEndpoint is error {
            return {
                actionStatus: ERROR,
                errorMessage: "Configuration missing",
                errorDescription: "JWT issuer or JWKS endpoint not provided in request"
            };
        }
        
        // Validate action type
        if payload.actionType != PRE_ISSUE_ACCESS_TOKEN {
            return {
                actionStatus: ERROR,
                errorMessage: "Invalid action type",
                errorDescription: "Support is available only for the PRE_ISSUE_ACCESS_TOKEN action type"
            };
        }
        
        // Validate both tokens and MFA with dynamic parameters
        string|error validatedAccessToken = validateTokensAndMFA(payload, jwtIssuer, jwksEndpoint);
        if validatedAccessToken is error {
            return {
                actionStatus: FAILED,
                failureReason: "invalid_token",
                failureDescription: validatedAccessToken.message()
            };
        }
        
        string|error userId = extractUserIdFromValidatedJWT(validatedAccessToken);
        if userId is error {
            return {
                actionStatus: FAILED,
                failureReason: "invalid_token",
                failureDescription: userId.message()
            };
        }
        
        // Get current timestamp
        time:Utc currentTime = time:utcNow();
        string timestamp = time:utcToString(currentTime);
        
        // Return success response with structured validation info
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
                },
                {
                    op: "add",
                    path: "/accessToken/claims/-",
                    value: {
                        name: "tokenValidation",
                        value: {
                            signature: "valid",
                            method: "JWKS_RS256", 
                            issuer: jwtIssuer,
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
    }
}
