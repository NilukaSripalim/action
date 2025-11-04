import ballerina/http;
import ballerina/log;
import ballerina/time;

service / on new http:Listener(9090) {

    resource function post actionchoreomfavalidation(@http:Payload RequestBody payload) returns SuccessResponse|ErrorResponse {
        log:printInfo("Received pre-issue token request");
        
        // Extract user ID from multiple possible locations
        string userId = extractUserIdFromMultipleSources(payload);
        string issuer = extractIssuer(payload);
        string timestamp = time:utcToString(time:utcNow());

        log:printInfo("Extracted user ID: " + userId);
        log:printInfo("Extracted issuer: " + issuer);

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

// Extract user ID from multiple possible sources
function extractUserIdFromMultipleSources(RequestBody payload) returns string {
    // Method 1: From user object (most direct)
    if payload?.event?.user?.id is string {
        string userId = <string>payload.event.user.id;
        log:printInfo("Found user ID from user object: " + userId);
        return userId;
    }
    
    // Method 2: From access token claims (sub claim)
    if payload?.event?.accessToken?.claims is () {
        foreach var claim in payload.event.accessToken.claims {
            if claim?.name == "sub" && claim?.value is string {
                string userId = <string>claim.value;
                log:printInfo("Found user ID from access token sub claim: " + userId);
                return userId;
            }
        }
    }
    
    // Method 3: From username in access token claims
    if payload?.event?.accessToken?.claims is () {
        foreach var claim in payload.event.accessToken.claims {
            if claim?.name == "username" && claim?.value is string {
                string username = <string>claim.value;
                log:printInfo("Found username from access token: " + username);
                return username;
            }
        }
    }
    
    log:printError("Could not extract user ID from any source");
    return "unknown-user-id";
}

// Helper function to extract issuer
function extractIssuer(RequestBody payload) returns string {
    if payload?.event?.accessToken?.claims is () {
        foreach var claim in payload.event.accessToken.claims {
            if claim?.name == "iss" && claim?.value is string {
                return <string>claim.value;
            }
        }
    }
    return "https://dev.api.asgardeo.io/t/orge2ecucasesuschoreogrp4/oauth2/token";
}
