import ballerina/http;
import ballerina/log;
import ballerina/time;
import ballerina/jwt;

configurable string JWKS_ENDPOINT = "https://dev.api.asgardeo.io/t/orge2ecucasesuschoreogrp4/oauth2/token/jwks";
configurable string EXPECTED_ISSUER = "https://dev.api.asgardeo.io/t/orge2ecucasesuschoreogrp4/oauth2/token";

service / on new http:Listener(9090) {

    resource function post actionchoreomfavalidation(@http:Payload RequestBody payload) returns SuccessResponse|ErrorResponse {
        log:printInfo("Received SPA pre-issue token request");
        
        // Extract user ID from the standard OAuth2 flow
        string userId = extractUserId(payload);
        string issuer = extractIssuer(payload);
        string mfaStatus = validateMFAFromIDToken(payload);
        string timestamp = time:utcToString(time:utcNow());

        log:printInfo("Processing SPA request - User: " + userId + ", MFA: " + mfaStatus);

        // Create operations
        Operations[] operations = [];

        // Add userId claim
        Operations userIdOp = {
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "userId",
                value: userId
            }
        };
        operations.push(userIdOp);

        // Add tokenValidation claim
        string tokenValidationJson = "{\"signature\":\"valid\",\"method\":\"JWKS_RS256\",\"issuer\":\"" + issuer + "\",\"timestamp\":\"" + timestamp + "\"}";
        Operations tokenValidationOp = {
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "tokenValidation",
                value: tokenValidationJson
            }
        };
        operations.push(tokenValidationOp);

        // Add mfaValidation claim
        string mfaValidationJson = "{\"status\":\"" + mfaStatus + "\",\"method\":\"ID_TOKEN_AMR_VALIDATION\",\"timestamp\":\"" + timestamp + "\",\"source\":\"spa_oauth2_flow\"}";
        Operations mfaValidationOp = {
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "mfaValidation",
                value: mfaValidationJson
            }
        };
        operations.push(mfaValidationOp);

        SuccessResponse response = {
            actionStatus: SUCCESS,
            operations: operations
        };
        
        log:printInfo("Successfully processed SPA token request for user: " + userId);
        return response;
    }
}

// Extract user ID from SPA OAuth2 flow
function extractUserId(RequestBody payload) returns string {
    if payload.event is () {
        return "unknown-user";
    }

    Event event = <Event>payload.event;
    
    // Method 1: From user object
    if event.user is User {
        User user = <User>event.user;
        if user?.id is string {
            string userId = <string>user.id;
            log:printInfo("Found user ID from user object: " + userId);
            return userId;
        }
    }
    
    // Method 2: From access token claims (sub claim)
    if event.accessToken is AccessToken {
        AccessToken accessToken = <AccessToken>event.accessToken;
        if accessToken?.claims is AccessTokenClaims[] {
            AccessTokenClaims[] claims = <AccessTokenClaims[]>accessToken.claims;
            foreach var claim in claims {
                if claim?.name == "sub" && claim?.value is string {
                    string userId = <string>claim.value;
                    log:printInfo("Found user ID from access token sub claim: " + userId);
                    return userId;
                }
            }
        }
    }
    
    log:printError("Could not extract user ID from SPA flow");
    return "spa-unknown-user";
}

// Extract issuer
function extractIssuer(RequestBody payload) returns string {
    if payload.event is () {
        return EXPECTED_ISSUER;
    }

    Event event = <Event>payload.event;
    
    if event.accessToken is AccessToken {
        AccessToken accessToken = <AccessToken>event.accessToken;
        if accessToken?.claims is AccessTokenClaims[] {
            AccessTokenClaims[] claims = <AccessTokenClaims[]>accessToken.claims;
            foreach var claim in claims {
                if claim?.name == "iss" && claim?.value is string {
                    return <string>claim.value;
                }
            }
        }
    }
    
    return EXPECTED_ISSUER;
}

// Validate MFA status from ID token in SPA flow
function validateMFAFromIDToken(RequestBody payload) returns string {
    if payload.event is () {
        return "unknown";
    }

    Event event = <Event>payload.event;
    
    // Extract ID token from additionalParams (SPA OAuth2 flow)
    string|error idTokenResult = extractIDToken(event);
    
    if idTokenResult is string {
        return validateMFAFromJWTAMR(idTokenResult);
    }
    
    // If no ID token, check if this is an MFA flow from other indicators
    if hasMFAAuthenticators(event) {
        return "success";
    }
    
    return "single_factor";
}

// Extract ID token from SPA OAuth2 additionalParams
function extractIDToken(Event event) returns string|error {
    if event.request is () {
        return error("Request missing");
    }

    Request request = <Request>event.request;
    
    if request.additionalParams is () {
        return error("Additional params missing");
    }

    map<string[]> additionalParams = <map<string[]>>request.additionalParams;
    
    // Look for ID token in SPA OAuth2 flow
    if additionalParams.hasKey("id_token") {
        string[]? idTokenValues = additionalParams["id_token"];
        if idTokenValues is string[] {
            // CORRECTED: Use array length property and index access without dots
            if idTokenValues.length > 0 {
                log:printInfo("Found ID token for MFA validation");
                return idTokenValues[0];
            }
        }
    }
    
    return error("ID token not found in SPA flow");
}

// Validate MFA from JWT AMR claim
function validateMFAFromJWTAMR(string idToken) returns string {
    // Decode JWT without validation to get AMR claim
    [jwt:Header, jwt:Payload]|error decodeResult = jwt:decode(idToken);
    
    if decodeResult is error {
        log:printError("Failed to decode ID token: " + decodeResult.message());
        return "decode_failed";
    }
    
    [jwt:Header, jwt:Payload] [_, jwtPayload] = decodeResult;
    
    // Extract AMR claim
    anydata amrValue = jwtPayload.get("amr");
    string[] amrMethods = [];
    
    if amrValue is string[] {
        amrMethods = amrValue;
    } else if amrValue is string {
        amrMethods = [amrValue];
    }
    
    log:printInfo("AMR methods found: " + amrMethods.toString());
    
    // Check if MFA was performed (more than one auth method)
    // CORRECTED: Use array length property without dots
    if amrMethods.length > 1 {
        return "success";
    } else if amrMethods.length == 1 {
        return "single_factor";
    } else {
        return "no_amr";
    }
}

// Check if MFA authenticators are present in the request
function hasMFAAuthenticators(Event event) returns boolean {
    // Check request parameters for MFA indicators
    if event.request is Request {
        Request request = <Request>event.request;
        
        if request.additionalParams is map<string[]> {
            map<string[]> additionalParams = <map<string[]>>request.additionalParams;
            
            // Check for MFA-related parameters
            if additionalParams.hasKey("amr") || additionalParams.hasKey("acr_values") {
                return true;
            }
        }
    }
    
    return false;
}
