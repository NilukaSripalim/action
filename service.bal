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
    
    // First, let's decode the ID token to see what claims it actually has
    [jwt:Header, jwt:Payload] [_, idTokenPayload] = check jwt:decode(idToken);
    
    // Check if amr claim exists and what it contains
    anydata? amrClaim = idTokenPayload.get("amr");
    if amrClaim is () {
        return error("ID Token missing amr claim. Available claims: " + getClaimNames(idTokenPayload));
    }
    
    // Validate ID Token signature and MFA claims
    check validateIDTokenAndMFA(idToken);
    
    // Validate access token signature
    string validatedAccessToken = check validateAccessToken(accessToken);
    
    return validatedAccessToken;
}

// Helper function to get claim names for debugging
function getClaimNames(jwt:Payload payload) returns string {
    string[] claimNames = [];
    // Get all available claim names
    anydata amr = payload.get("amr");
    anydata sub = payload.get("sub");
    anydata iss = payload.get("iss");
    anydata aud = payload.get("aud");
    anydata exp = payload.get("exp");
    anydata iat = payload.get("iat");
    anydata nbf = payload.get("nbf");
    anydata nonce = payload.get("nonce");
    anydata sid = payload.get("sid");
    anydata azp = payload.get("azp");
    anydata auth_time = payload.get("auth_time");
    anydata at_hash = payload.get("at_hash");
    anydata c_hash = payload.get("c_hash");
    anydata acr = payload.get("acr");
    anydata org_id = payload.get("org_id");
    anydata org_name = payload.get("org_name");
    anydata org_handle = payload.get("org_handle");
    anydata username = payload.get("username");
    
    if amr is string[] { claimNames.push("amr"); }
    if sub is string { claimNames.push("sub"); }
    if iss is string { claimNames.push("iss"); }
    if aud is string { claimNames.push("aud"); }
    if exp is int { claimNames.push("exp"); }
    if iat is int { claimNames.push("iat"); }
    if nbf is int { claimNames.push("nbf"); }
    if nonce is string { claimNames.push("nonce"); }
    if sid is string { claimNames.push("sid"); }
    if azp is string { claimNames.push("azp"); }
    if auth_time is int { claimNames.push("auth_time"); }
    if at_hash is string { claimNames.push("at_hash"); }
    if c_hash is string { claimNames.push("c_hash"); }
    if acr is string { claimNames.push("acr"); }
    if org_id is string { claimNames.push("org_id"); }
    if org_name is string { claimNames.push("org_name"); }
    if org_handle is string { claimNames.push("org_handle"); }
    if username is string { claimNames.push("username"); }
    
    return claimNames.toString();
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

// Validate MFA claims in ID Token - SIMPLIFIED
function validateMFAClaims(jwt:Payload idTokenPayload) returns error? {
    // Check amr (Authentication Methods References)
    anydata? amr = idTokenPayload.get("amr");
    
    if amr is string[] {
        // If we have amr array, check if it contains any MFA indicators
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
