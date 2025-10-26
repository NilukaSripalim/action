import ballerina/http;
import ballerina/jwt;
import ballerina/log;
import ballerina/io;

configurable boolean enabledDebugLog = true;

// Test certificate for RS256 validation - using heredoc syntax
const string TEST_CERTIFICATE = string`-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEVHJsoDANBgkqhkiG9w0BAQsFADBsMRAwDgYDVQQGEwdV
bmtub3duMRAwDgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYD
VQQKEwdVbmtub3duMRAwDgYDVQQLEwdVbmtub3duMRAwDgYDVQQDEwdVbmtub3du
MB4XDTIzMDMxNTA3MzIzN1oXDTM0MDIyNTA3MzIzN1owbDEQMA4GA1UEBhMHVW5r
bm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93bjEQMA4GA1UE
ChMHVW5rbm93bjEQMA4GA1UECxMHVW5rbm93bjEQMA4GA1UEAxMHVW5rbm93bjCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJBeF8561LSr2VICeyAsWIjr
3n9XGGPUFjKBouTckwDTKNxjWPKvDfgoJ860/YDru1MSDV712um0UsLtCO15z3kt
fUvxIITzq/nUnbqup3PGVIKkTbRO1NgR4D0/WchGwUzD96chgXiEW8fVZvUhao1e
Osz1C9py9z3gDTio1DG0VAG/ULW2jUlrD+ptXpe28wZedSZCA7RyBlIXGCCVF2Nm
P0X04o0ye8R4EDa25N2r1DqdOXS22VHVcBLpTkVsV5di6xozdwCXCqGt+g//DZn+
njRGnM5Z/f1ScPcBebZDWp1A1MGhKa/PZ60Q/tMf0Qihkeji02+bydZPH0398tcC
AwEAAaMhMB8wHQYDVR0OBBYEFC9yJi59DKWax/Hl4GajqCQTxvqKMA0GCSqGSIb3
DQEBCwUAA4IBAQB11iZYR6iq8QRIvLM5RFvjf/UUjjzn4W0rWXCytM9UZsOD+NmE
3DW8rfI0mjJwJsokL6xyIIpb733fMsxC646+FKO7mnOiVcpMR63dBQ5SDjY95RGM
ET0UaEBPji8fKbeebJXpLJt5tlqPFAc9M7xPIXKvfw+/9LlCaQJvFLOF3+Tws/xq
wNa5WvVh3DRs2kgyN/tFvt3enI4TpOEu3bBSbxh7d7E/HUJOz9ScM9cE3sjlNtwK
AzQEMAZD+Vc1cF8GAgURydWPVicaiIAr4kkmUMex4rt4b97Wd7PuZbp32O+iFKMG
u2ahQ9ernk2xYni6ZPXn/u0CwaZJ3jSALzyQ
-----END CERTIFICATE-----`;

// Extract JWT from additionalParams and validate signature with certificate
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
    
    // 4. Validate based on algorithm - Now using RS256 with certificate
    jwt:Payload|error validationResult;
    
    if algorithm == "RS256" {
        if enabledDebugLog {
            log:printInfo("🔄 Using RS256 validation with certificate");
        }
        
        // Write certificate to temporary file for validation
        string tempCertPath = "/tmp/test_cert.pem";
        check io:fileWriteString(tempCertPath, TEST_CERTIFICATE);
        
        jwt:ValidatorConfig validatorConfig = {
            issuer: "wso2",
            clockSkew: 60,
            signatureConfig: {
                certFile: tempCertPath
            }
        };
        validationResult = jwt:validate(jwtToken, validatorConfig);
    } else {
        return error("Unsupported JWT algorithm: " + algorithm.toString() + ". Expected RS256");
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
    
    // Try to get userId from JWT claims
    anydata? userIdClaim = jwtPayload.get("userId");
    if userIdClaim is string {
        return userIdClaim;
    }
    
    // Alternative: use "sub" claim if userId not present
    anydata? subClaim = jwtPayload.get("sub");
    if subClaim is string {
        return subClaim;
    }
    
    // Try username claim
    anydata? usernameClaim = jwtPayload.get("username");
    if usernameClaim is string {
        return usernameClaim;
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
        if enabledDebugLog {
            log:printInfo("📥 Pre-Issue Access Token action triggered");
            log:printInfo(string `Request ID: ${payload.requestId ?: "unknown"}`);
            log:printInfo(string `Action Type: ${payload.actionType.toString()}`);
            log:printInfo(string `Grant Type: ${payload.event?.request?.grantType ?: "unknown"}`);
        }
        
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
        
        if enabledDebugLog {
            log:printInfo(string `✅ Extracted userId from validated JWT: ${userId}`);
            log:printInfo("🔐 JWT Signature Validated: YES");
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
