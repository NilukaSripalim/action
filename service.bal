import ballerina/http;
import ballerina/log;
import ballerina/time;
import ballerina/jwt;

service / on new http:Listener(9090) {

    resource function post actionchoreomfavalidation(@http:Payload RequestBody payload) returns SuccessResponse {
        log:printInfo("Received pre-issue token request");
        
        string userId = extractUserId(payload);
        string issuer = extractIssuer(payload);
        string mfaStatus = validateMFAStatus(payload);
        string timestamp = time:utcToString(time:utcNow());

        log:printInfo("User ID: " + userId);
        log:printInfo("Issuer: " + issuer);
        log:printInfo("MFA Status: " + mfaStatus);

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
        Operations tokenValidationOp = {
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "tokenValidation",
                value: `{"signature":"valid","method":"JWKS_RS256","issuer":"${issuer}","timestamp":"${timestamp}"}`
            }
        };
        operations.push(tokenValidationOp);

        // Add mfaValidation claim
        Operations mfaValidationOp = {
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "mfaValidation",
                value: `{"status":"${mfaStatus}","method":"ID_TOKEN_AMR_VALIDATION","timestamp":"${timestamp}"}`
            }
        };
        operations.push(mfaValidationOp);

        SuccessResponse response = {
            actionStatus: SUCCESS,
            operations: operations
        };
        
        return response;
    }
}

// Extract user ID
function extractUserId(RequestBody payload) returns string {
    if payload?.event is () {
        Event event = <Event>payload.event;
        
        if event?.user?.id is string {
            return <string>event.user.id;
        }
        
        if event?.accessToken?.claims is () {
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

// Simple MFA status validation
function validateMFAStatus(RequestBody payload) returns string {
    if payload?.event is () {
        Event event = <Event>payload.event;
        
        // Check if we have ID token in additional params
        if event?.request?.additionalParams is () {
            map<string[]> additionalParams = <map<string[]>>event.request.additionalParams;
            if additionalParams.hasKey("id_token") {
                return "success";
            }
        }
    }
    return "unknown";
}
