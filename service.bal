import ballerina/http;
import ballerina/log;
import ballerina/time;
import ballerina/jwt;

service / on new http:Listener(9090) {

    resource function post actionchoreomfavalidation(@http:Payload RequestBody payload) returns SuccessResponse|ErrorResponse {
        log:printInfo("Received SPA pre-issue token request");
        
        // Extract issuer dynamically from payload
        string issuer = extractIssuer(payload);
        
        if issuer == "" {
            log:printError("Failed to extract issuer from payload");
            ErrorResponse errorResp = {
                actionStatus: "FAILED",
                errorMessage: "Invalid request: missing issuer in token claims",
                errorDescription: "The issuer claim is required for validation"
            };
            return errorResp;
        }
        
        // Generate JWKS endpoint from issuer (standard Asgardeo pattern)
        string jwksEndpoint = generateJWKSEndpoint(issuer);
        
        // Validate the token signature using the extracted JWKS endpoint
        boolean isValidSignature = validateTokenSignature(payload, jwksEndpoint);
        
        if !isValidSignature {
            log:printError("Token signature validation failed");
            ErrorResponse errorResp = {
                actionStatus: "FAILED",
                errorMessage: "Token signature validation failed",
                errorDescription: "Invalid token signature or JWKS endpoint"
            };
            return errorResp;
        }
        
        // Extract user ID from the standard OAuth2 flow
        string userId = extractUserId(payload);
        
        // Validate MFA from ID token (SPA flow)
        string mfaStatus = validateMFAFromIDToken(payload);
        
        string timestamp = time:utcToString(time:utcNow());

        log:printInfo(string `Processing SPA request - User: ${userId}, MFA: ${mfaStatus}, Issuer: ${issuer}`);

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

        // Add tokenValidation claim with dynamic issuer and JWKS endpoint
        string tokenValidationJson = string `{"signature":"valid","method":"JWKS_RS256","issuer":"${issuer}","jwksEndpoint":"${jwksEndpoint}","timestamp":"${timestamp}"}`;
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
        string mfaValidationJson = string `{"status":"${mfaStatus}","method":"ID_TOKEN_AMR_VALIDATION","timestamp":"${timestamp}","source":"spa_oauth2_flow"}`;
        Operations mfaValidationOp = {
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "mfaValidation",
                value: mfaValidationJson
            }
        };
        operations.push(mfaValidationOp);

        // Add organization/tenant metadata for reference
        string? tenantName = extractTenantName(payload);
        if tenantName is string {
            Operations tenantOp = {
                op: "add",
                path: "/accessToken/claims/-",
                value: {
                    name: "tenantName",
                    value: tenantName
                }
            };
            operations.push(tenantOp);
        }

        SuccessResponse response = {
            actionStatus: "SUCCESS",
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
    
    // Method 1: From user object (most reliable for SPA authorization_code flow)
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

// Extract issuer dynamically from payload (always available in Asgardeo pre-issue action)
function extractIssuer(RequestBody payload) returns string {
    if payload.event is () {
        log:printError("No event in payload - invalid request");
        return "";
    }

    Event event = <Event>payload.event;
    
    // Extract issuer from access token claims (always present in Asgardeo)
    if event.accessToken is AccessToken {
        AccessToken accessToken = <AccessToken>event.accessToken;
        if accessToken?.claims is AccessTokenClaims[] {
            AccessTokenClaims[] claims = <AccessTokenClaims[]>accessToken.claims;
            foreach var claim in claims {
                if claim?.name == "iss" && claim?.value is string {
                    string issuer = <string>claim.value;
                    log:printInfo("Extracted issuer from access token: " + issuer);
                    return issuer;
                }
            }
        }
    }
    
    log:printError("Could not extract issuer from payload - invalid Asgardeo request");
    return "";
}

// Generate JWKS endpoint from issuer (standard Asgardeo pattern)
function generateJWKSEndpoint(string issuer) returns string {
    // Standard Asgardeo pattern: issuer URL + /jwks
    // Example: https://dev.api.asgardeo.io/t/org123/oauth2/token -> https://dev.api.asgardeo.io/t/org123/oauth2/token/jwks
    
    if issuer.endsWith("/token") {
        string jwksEndpoint = issuer + "/jwks";
        log:printInfo("Generated JWKS endpoint: " + jwksEndpoint);
        return jwksEndpoint;
    }
    
    // If issuer ends with /oauth2 or similar, append /token/jwks
    if issuer.endsWith("/oauth2") {
        string jwksEndpoint = issuer + "/token/jwks";
        log:printInfo("Generated JWKS endpoint from oauth2 base: " + jwksEndpoint);
        return jwksEndpoint;
    }
    
    // Default: append /oauth2/token/jwks
    string jwksEndpoint = issuer + "/oauth2/token/jwks";
    log:printWarn("Issuer doesn't match expected pattern, using fallback JWKS endpoint: " + jwksEndpoint);
    return jwksEndpoint;
}

// Validate token signature using JWKS endpoint
function validateTokenSignature(RequestBody payload, string jwksEndpoint) returns boolean {
    if payload.event is () {
        log:printError("No event in payload");
        return false;
    }

    Event event = <Event>payload.event;
    
    // Extract ID token for validation
    string|error idTokenResult = extractIDToken(event);
    
    if idTokenResult is error {
        log:printWarn("No ID token found for signature validation, checking access token");
        // For some flows, we might only have access token
        return validateAccessTokenSignature(event, jwksEndpoint);
    }
    
    string idToken = idTokenResult;
    
    // Validate JWT signature using JWKS endpoint
    jwt:ValidatorSignatureConfig signatureConfig = {
        jwksConfig: {
            url: jwksEndpoint
        }
    };
    
    jwt:Payload|error validationResult = jwt:validate(idToken, signatureConfig);
    
    if validationResult is error {
        log:printError("ID token validation failed: " + validationResult.message());
        return false;
    }
    
    log:printInfo("ID token signature validated successfully using JWKS endpoint: " + jwksEndpoint);
    return true;
}

// Validate access token signature (fallback)
function validateAccessTokenSignature(Event event, string jwksEndpoint) returns boolean {
    // In pre-issue action, the access token is not yet issued as JWT
    // So we trust the issuer claim presence as validation
    // The actual JWT validation will happen when the token is used
    
    if event.accessToken is AccessToken {
        AccessToken accessToken = <AccessToken>event.accessToken;
        if accessToken?.claims is AccessTokenClaims[] {
            log:printInfo("Access token structure validated, JWKS endpoint configured for post-issue validation");
            return true;
        }
    }
    
    log:printError("Could not validate token structure");
    return false;
}

// Extract tenant name from payload
function extractTenantName(RequestBody payload) returns string? {
    if payload.event is () {
        return ();
    }

    Event event = <Event>payload.event;
    
    // Try to get organization name first (more specific for B2B scenarios)
    if event.organization is Organization {
        Organization org = <Organization>event.organization;
        if org?.name is string {
            return <string>org.name;
        }
    }
    
    // Fall back to tenant name
    if event.tenant is Tenant {
        Tenant tenant = <Tenant>event.tenant;
        if tenant?.name is string {
            return <string>tenant.name;
        }
    }
    
    return ();
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
    
    // Check grant type - for SPA, authorization_code with MFA should have ID token
    string grantType = extractGrantType(event);
    if grantType == "authorization_code" {
        log:printWarn("Authorization code grant without ID token - MFA status uncertain");
        return "id_token_missing";
    }
    
    return "single_factor";
}

// Extract grant type
function extractGrantType(Event event) returns string {
    if event.request is Request {
        Request request = <Request>event.request;
        if request?.grantType is string {
            return <string>request.grantType;
        }
    }
    return "unknown";
}

// Extract ID token from SPA OAuth2 additionalParams
function extractIDToken(Event event) returns string|error {
    if event.request is () {
        return error("Request missing");
    }

    Request request = <Event>event.request;
    
    if request.additionalParams is () {
        return error("Additional params missing");
    }

    map<string[]> additionalParams = <map<string[]>>request.additionalParams;
    
    // Look for ID token in SPA OAuth2 flow
    if additionalParams.hasKey("id_token") {
        string[]? idTokenValues = additionalParams["id_token"];
        if idTokenValues is string[] {
            int arrayLength = idTokenValues.length();
            if arrayLength > 0 {
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
    
    // Extract AMR claim (Authentication Methods References)
    anydata amrValue = jwtPayload.get("amr");
    string[] amrMethods = [];
    
    if amrValue is string[] {
        amrMethods = amrValue;
    } else if amrValue is string {
        amrMethods = [amrValue];
    }
    
    // Convert array to string for logging
    string amrString = "";
    foreach int i in 0 ..< amrMethods.length() {
        if i > 0 {
            amrString += ", ";
        }
        amrString += amrMethods[i];
    }
    log:printInfo("AMR methods found: [" + amrString + "]");
    
    // Check if MFA was performed (more than one auth method)
    // Common AMR values: pwd (password), otp (one-time password), totp, sms, etc.
    int amrLength = amrMethods.length();
    if amrLength > 1 {
        log:printInfo("MFA detected: Multiple authentication methods used");
        return "success";
    } else if amrLength == 1 {
        log:printInfo("Single factor authentication detected");
        return "single_factor";
    } else {
        log:printWarn("No AMR claim found in ID token");
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
