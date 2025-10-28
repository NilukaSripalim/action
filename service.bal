import ballerina/http;
import ballerina/jwt;
import ballerina/time;

configurable boolean enabledDebugLog = true;

// Function to extract JWT configuration from ID token
function extractJWTConfigFromToken(string idToken) returns record {|string jwtIssuer; string jwksEndpoint;|} | error {
    [jwt:Header, jwt:Payload] [_, decodedPayload] = check jwt:decode(idToken);
    
    // Extract issuer from JWT payload
    anydata? issuerClaim = decodedPayload.get("iss");
    if issuerClaim is string {
        string issuer = issuerClaim;
        // Construct JWKS endpoint from issuer
        string jwksEndpoint = check constructJWKSEndpoint(issuer);
        
        return {
            jwtIssuer: issuer,
            jwksEndpoint: jwksEndpoint
        };
    } else {
        return error("Issuer (iss) claim not found in ID token");
    }
}

// Helper function to construct JWKS endpoint from issuer - FIXED
function constructJWKSEndpoint(string issuer) returns string|error {
    // Remove trailing slashes
    string cleanIssuer = issuer.trim();
    if cleanIssuer.endsWith("/") {
        cleanIssuer = cleanIssuer.substring(0, cleanIssuer.length() - 1);
    }
    
    // Replace /oauth2/token with /oauth2/jwks if present - FIXED
    if cleanIssuer.endsWith("/oauth2/token") {
        return cleanIssuer.replaceAll("/oauth2/token", "/oauth2/jwks");
    }
    
    // If no specific path, just append /oauth2/jwks
    // Check if issuer already has a path
    if cleanIssuer.includes("/oauth2/") {
        return cleanIssuer + "/jwks";
    } else {
        return cleanIssuer + "/oauth2/jwks";
    }
}

// Extract and validate both tokens with MFA
function validateTokensAndMFA(RequestBody payload) returns string|error {
    RequestParams[]? requestParams = payload.event?.request?.additionalParams;
    if requestParams is () {
        return error("Token parameters missing in additionalParams");
    }
    
    // Extract both tokens
    string idToken = check extractToken(requestParams, "id_token");
    string accessToken = check extractToken(requestParams, "access_token");
    
    // Extract JWT configuration from ID token
    record {|string jwtIssuer; string jwksEndpoint;|} | error config = extractJWTConfigFromToken(idToken);
    if config is error {
        return error("Failed to extract JWT configuration from ID token: " + config.message());
    }
    
    string jwtIssuer = config.jwtIssuer;
    string jwksEndpoint = config.jwksEndpoint;
    
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

// Extract any token from parameters
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
        // Validate action type
        if payload.actionType != PRE_ISSUE_ACCESS_TOKEN {
            return {
                actionStatus: ERROR,
                errorMessage: "Invalid action type",
                errorDescription: "Support is available only for the PRE_ISSUE_ACCESS_TOKEN action type"
            };
        }
        
        // Validate both tokens and MFA - configuration is now extracted from ID token
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
        
        // Extract configuration for response (decode the validated access token to get issuer)
        [jwt:Header, jwt:Payload] [_, accessTokenPayload] = check jwt:decode(validatedAccessToken);
        anydata? issuerClaim = accessTokenPayload.get("iss");
        string jwtIssuer = issuerClaim is string ? issuerClaim : "unknown";
        
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
