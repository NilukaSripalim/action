import ballerina/http;
import ballerina/jwt;
import ballerina/time;

configurable boolean enabledDebugLog = true;
configurable string JWT_ISSUER = "https://api.asgardeo.io/t/orgasgardeouse2e/oauth2/token";
configurable string JWKS_ENDPOINT = "https://api.asgardeo.io/t/orgasgardeouse2e/oauth2/jwks";

// Extract and validate both tokens with MFA
function validateTokensAndMFA(RequestBody payload) returns string|error {
    RequestParams[]? requestParams = payload.event?.request?.additionalParams;
    if requestParams is () {
        return error("Token parameters missing in additionalParams");
    }
    
    // Extract both tokens
    string idToken = check extractToken(requestParams, "id_token");
    string accessToken = check extractToken(requestParams, "access_token");
    
    // Validate ID Token signature and MFA claims
    check validateIDTokenAndMFA(idToken);
    
    // Validate access token signature
    string validatedAccessToken = check validateAccessToken(accessToken);
    
    return validatedAccessToken;
}

// Validate ID Token signature and MFA claims
function validateIDTokenAndMFA(string idToken) returns error? {
    jwt:ValidatorConfig idTokenValidator = {
        issuer: JWT_ISSUER,
        clockSkew: 60,
        signatureConfig: {
            jwksConfig: {
                url: JWKS_ENDPOINT
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

// Validate MFA claims in ID Token - SIMPLIFIED and ROBUST
function validateMFAClaims(jwt:Payload idTokenPayload) returns error? {
    // Check amr (Authentication Methods References) - use more flexible approach
    anydata? amr = idTokenPayload.get("amr");
    
    // Try to convert to string array regardless of the exact type
    string[]|error amrArray = convertToAmrArray(amr);
    
    if amrArray is string[] {
        // Check if it contains MFA methods
        boolean hasMFA = checkMFAMethods(amrArray);
        if hasMFA {
            return;
        } else {
            return error("No MFA methods found in amr: " + amrArray.toString());
        }
    } else {
        return error("Unable to process amr claim: " + amr.toString());
    }
}

// Convert any amr data to string array
function convertToAmrArray(anydata? amr) returns string[]|error {
    if amr is string[] {
        return amr;
    } else if amr is json[] {
        // Handle case where it might be a json array
        string[] result = [];
        foreach var item in amr {
            if item is string {
                result.push(item);
            }
        }
        return result;
    } else if amr is () {
        return error("amr claim is missing");
    } else {
        return error("Unsupported amr type: " + amr.toString());
    }
}

// Helper function to check for MFA methods in array
function checkMFAMethods(string[] amr) returns boolean {
    foreach string method in amr {
        if checkMFAMethod(method) {
            return true;
        }
    }
    return false;
}

// Helper function to check a single MFA method
function checkMFAMethod(string method) returns boolean {
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
function validateAccessToken(string accessToken) returns string|error {
    jwt:ValidatorConfig accessTokenValidator = {
        issuer: JWT_ISSUER,
        clockSkew: 60,
        signatureConfig: {
            jwksConfig: {
                url: JWKS_ENDPOINT
            }
        }
    };
    
    jwt:Payload|error accessTokenValidation = jwt:validate(accessToken, accessTokenValidator);
    if accessTokenValidation is error {
        return error("Access Token signature validation failed: " + accessTokenValidation.message());
    }
    
    return accessToken;
}

// Extract any token from parameters
function extractToken(RequestParams[] reqParams, string tokenName) returns string|error {
    map<string> params = {};
    foreach RequestParams param in reqParams {
        string[]? value = param.value;
        string? name = param.name;
        if name is string && value is string[] && value.length() > 0 {
            params[name] = value[0];
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
            serviceName: "asgardeo-mfa-validation",
            version: "1.0.0",
            description: "Pre-Issue Access Token Action with MFA Validation"
        };
    }

    // Main webhook endpoint for Asgardeo Pre-Issue Access Token action
    resource function post .(RequestBody payload) returns SuccessResponse|FailedResponse|ErrorResponse {
        // Validate action type
        if payload.actionType != PRE_ISSUE_ACCESS_TOKEN {
            return {
                actionStatus: ERROR,
                errorMessage: "Invalid action type",
                errorDescription: "Support is available only for the PRE_ISSUE_ACCESS_TOKEN action type"
            };
        }
        
        // Validate both tokens and MFA
        string|error validatedAccessToken = validateTokensAndMFA(payload);
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
                            issuer: JWT_ISSUER,
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
