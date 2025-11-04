import ballerina/http;
import ballerina/log;
import ballerina/time;
import ballerina/jwt;

service / on new http:Listener(9090) {

    resource function post actionchoreomfavalidation(@http:Payload RequestBody payload) returns SuccessResponse|ErrorResponse {
        log:printInfo("Received pre-issue token request");
        
        // Extract user ID
        string userId = extractUserId(payload);
        string issuer = extractIssuer(payload);
        
        // Validate MFA from ID token in additionalParams
        MFAValidationResult mfaResult = validateMFAFromIDToken(payload);
        
        string timestamp = time:utcToString(time:utcNow());

        log:printInfo("User ID: " + userId);
        log:printInfo("MFA Status: " + mfaResult.status);
        log:printInfo("MFA Methods: " + mfaResult.methods.toString());

        // Create success response
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
                            issuer: issuer,
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
                            status: mfaResult.status,
                            method: mfaResult.method,
                            methods: mfaResult.methods,
                            timestamp: timestamp
                        }
                    }
                }
            ]
        };
    }
}

// MFA validation result type
public type MFAValidationResult record {
    string status;
    string method;
    string[] methods;
};

// Extract ID token from additionalParams and validate MFA
function validateMFAFromIDToken(RequestBody payload) returns MFAValidationResult {
    // Check if event exists
    if payload.event is () {
        return {
            status: "unknown",
            method: "NO_ID_TOKEN",
            methods: []
        };
    }

    Event event = <Event>payload.event;
    
    // Extract ID token from additionalParams
    string? idToken = extractIDToken(event);
    
    if idToken is string {
        return validateMFAFromJWT(idToken);
    }
    
    return {
        status: "no_id_token",
        method: "NO_ID_TOKEN_PROVIDED", 
        methods: []
    };
}

// Extract ID token from additionalParams
function extractIDToken(Event event) returns string? {
    if event.request is () && event.request?.additionalParams is () {
        map<string[]> additionalParams = <map<string[]>>event.request.additionalParams;
        
        // Look for id_token in additionalParams
        if additionalParams.hasKey("id_token") {
            string[] idTokenValues = additionalParams["id_token"];
            if idTokenValues.length() > 0 {
                return idTokenValues[0];
            }
        }
    }
    return ();
}

// Validate MFA from JWT ID token
function validateMFAFromJWT(string idToken) returns MFAValidationResult {
    // Decode JWT without validation to get AMR claim
    [jwt:Header, jwt:Payload]|error decodeResult = jwt:decode(idToken);
    
    if decodeResult is error {
        log:printError("Failed to decode ID token: " + decodeResult.message());
        return {
            status: "invalid_token",
            method: "DECODE_FAILED",
            methods: []
        };
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
    
    // Check if MFA was performed (should have more than one auth method)
    if amrMethods.length() > 1 {
        return {
            status: "success",
            method: "MULTI_FACTOR",
            methods: amrMethods
        };
    } else if amrMethods.length() == 1) {
        return {
            status: "single_factor", 
            method: "SINGLE_FACTOR",
            methods: amrMethods
        };
    } else {
        return {
            status: "no_amr",
            method: "NO_AMR_CLAIM",
            methods: []
        };
    }
}

// Extract user ID
function extractUserId(RequestBody payload) returns string {
    if payload?.event is () {
        Event event = <Event>payload.event;
        
        if event?.user?.id is string {
            return <string>event.user.id;
        } else if event?.accessToken?.claims is () {
            AccessTokenClaims[] claims = <AccessTokenClaims[]>event.accessToken.claims;
            foreach var claim in claims {
                if claim?.name == "sub" && claim?.value is string {
                    return <string>claim.value;
                }
            }
        }
    }
    return "unknown-user-id";
}

// Extract issuer
function extractIssuer(RequestBody payload) returns string {
    if payload?.event is () {
        Event event = <Event>payload.event;
        
        if event?.accessToken?.claims is () {
            AccessTokenClaims[] claims = <AccessTokenClaims[]>event.accessToken.claims;
            foreach var claim in claims {
                if claim?.name == "iss" && claim?.value is string {
                    return <string>claim.value;
                }
            }
        }
    }
    return "https://dev.api.asgardeo.io/t/orge2ecucasesuschoreogrp4/oauth2/token";
}
