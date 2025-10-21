import ballerina/http;
import ballerina/log;

enum ActionSuccessStatus {
    SUCCESS
}

enum ActionFailedStatus {
    ERROR
}

enum OperationType {
    ADD = "add",
    REMOVE = "remove",
    REPLACE = "replace"
}

type OperationValue record {
    string name;
    string | string[] | boolean value;
};

type Operation record {
    string op;
    string path;
    string | OperationValue value?;
};

type ActionSuccessResponse record {
    ActionSuccessStatus actionStatus;
    Operation[] operations;
};

type ActionFailedResponse record {
    ActionFailedStatus actionStatus;
    string 'error;
    string error_description;
};

service / on new http:Listener(8090) {
    resource function post preIssueAccessTokenUpdateScopes(http:Request req) returns http:Response|error? {

        ActionSuccessResponse respBody;
        http:Response resp = new;
        log:printInfo("Request Received to Update Scopes of the access token");
        json requestPayload = <json> check req.getJsonPayload();
        log:printInfo(requestPayload.toString());
        json grantType = check requestPayload.toJson().event.request.grantType;
        if (grantType == "refresh_token") {
            respBody = {
                "actionStatus": SUCCESS,
                "operations": [
                    {
                        op: REMOVE,
                        path: "/accessToken/scopes/0"
                    }
                ]
            };
        } else {
            respBody = {
                "actionStatus": SUCCESS,
                "operations": [
                    {
                        op: ADD,
                        path: "/accessToken/scopes/-",
                        value: "test_api_perm_3"
                    },
                    {
                        op: ADD,
                        path: "/accessToken/scopes/0",
                        value: "test_api_perm_2"
                    },
                    {
                        op: REMOVE,
                        path: "/accessToken/scopes/0"
                    },
                    {
                        op: REPLACE,
                        path: "/accessToken/scopes/1",
                        value: "test_api_perm_1"
                    }
                ]
            };
        }
        resp.statusCode = 200;
        resp.setJsonPayload(respBody.toJson());

        return resp;
    }

    resource function post preIssueAccessTokenUpdateAudience(http:Request req) returns http:Response|error? {
        
        ActionSuccessResponse respBody;
        http:Response resp = new;
        log:printInfo("Request Received to Update Audience of the access token");
        json requestPayload = <json> check req.getJsonPayload();
        log:printInfo(requestPayload.toString());
        json grantType = check requestPayload.toJson().event.request.grantType;
        if (grantType == "refresh_token") { 
            respBody = {
                "actionStatus": SUCCESS,
                "operations": [
                    {
                        op: REMOVE,
                        path: "/accessToken/claims/aud/0"
                    }
                ]
            };
        } else {
            respBody = {
                "actionStatus": SUCCESS,
                "operations": [
                    {
                        op: ADD,
                        path: "/accessToken/claims/aud/-",
                        value: "https://myextension.com"
                    },
                    {
                        op: REMOVE,
                        path: "/accessToken/claims/aud/1"
                    },
                    {
                        op: REPLACE,
                        path: "/accessToken/claims/aud/0",
                        value: "https://localhost:8090"
                    }
                ]
            };
        }
        resp.statusCode = 200;
        resp.setJsonPayload(respBody.toJson());

        return resp;
    }

    resource function post preIssueAccessTokenUpdateOidcClaims(http:Request req) returns http:Response|error? {

        ActionSuccessResponse respBody;
        http:Response resp = new;
        log:printInfo("Request Received to Update OIDC Claims of the access token");
        json requestPayload = <json> check req.getJsonPayload();
        log:printInfo(requestPayload.toString());
        json grantType = check requestPayload.toJson().event.request.grantType;
        if (grantType == "refresh_token") {
            respBody = {
                "actionStatus": SUCCESS,
                "operations": [
                    {
                        op: REMOVE,
                        path: "/accessToken/claims/groups/0"
                    }
                ]
            };
        } else {
            respBody = {
                "actionStatus": SUCCESS,
                "operations": [
                    {
                        op: REMOVE,
                        path: "/accessToken/claims/groups/0"
                    },
                    {
                        op: REPLACE,
                        path: "/accessToken/claims/groups/1",
                        value: "verifiedGroup1"
                    },
                    {
                        op: REPLACE,
                        path: "/accessToken/claims/username",
                        value: "US/JohnDoe"
                    }
                ]
            };
        }
        resp.statusCode = 200;
        resp.setJsonPayload(respBody.toJson());

        return resp;
    }

    resource function post preIssueAccessTokenUpdateTokenExpiryTime(http:Request req) returns http:Response|error? {
        
        ActionSuccessResponse respBody;
        http:Response resp = new;
        log:printInfo("Request Received to Update Expiry Time of the access token");
        json requestPayload = <json> check req.getJsonPayload();
        log:printInfo(requestPayload.toString());
        json grantType = check requestPayload.toJson().event.request.grantType;
        if (grantType == "refresh_token") {
            respBody = {
                "actionStatus": SUCCESS,
                "operations": [
                    {
                        op: REPLACE,
                        path: "/accessToken/claims/expires_in",
                        value: "3000"
                    }
                ]
            };
        } else {
            respBody = {
                "actionStatus": SUCCESS,
                "operations": [
                    {
                        op: REPLACE,
                        path: "/accessToken/claims/expires_in",
                        value: "4000"
                    }
                ]
            };
        }
        resp.statusCode = 200;
        resp.setJsonPayload(respBody.toJson());

        return resp;   
    }

    resource function post preIssueAccessTokenAddCustomClaims(http:Request req) returns http:Response|error? {
        
        ActionSuccessResponse respBody;
        http:Response resp = new;
        log:printInfo("Request Received to Add Custom Claims to the access token");
        json requestPayload = <json> check req.getJsonPayload();
        log:printInfo(requestPayload.toString());
        json grantType = check requestPayload.toJson().event.request.grantType;
        
        // Extract userID from the request payload
        string userID = check getUserIdFromRequest(requestPayload);
        log:printInfo("Adding userID to token: " + userID);
        
        if (grantType == "refresh_token") {
            string? prevGrantType = check getAccessTokenClaim(requestPayload, "grantType");
            if prevGrantType != null {
                respBody = {
                    "actionStatus": SUCCESS,
                    "operations": [
                        {
                            op: REPLACE,
                            path: "/accessToken/claims/grantType",
                            value: grantType.toString()
                        },
                        {
                            op: ADD,
                            path: "/accessToken/claims/-",
                            value: {
                                name: "previousGrantType",
                                value: prevGrantType
                            }
                        },
                        {
                            op: ADD,
                            path: "/accessToken/claims/-",
                            value: {
                                name: "userID",
                                value: userID
                            }
                        }
                    ]
                };
            } else {
                respBody = {
                    "actionStatus": SUCCESS,
                    "operations": [
                        {
                            op: ADD,
                            path: "/accessToken/claims/-",
                            value: {
                                name: "grantType",
                                value: grantType.toString()
                            }
                        },
                        {
                            op: ADD,
                            path: "/accessToken/claims/-",
                            value: {
                                name: "userID",
                                value: userID
                            }
                        }
                    ]
                };
            }
        } else {
            respBody = {
                "actionStatus": SUCCESS,
                "operations": [
                    {
                        op: ADD,
                        path: "/accessToken/claims/-",
                        value: {
                            name: "grantType",
                            value: grantType.toString()
                        }
                    },
                    {
                        op: ADD,
                        path: "/accessToken/claims/-",
                        value: {
                            name: "userID",
                            value: userID
                        }
                    },
                    {
                        op: ADD,
                        path: "/accessToken/claims/-",
                        value: {
                            name: "isPermanent",
                            value: true
                        }
                    },
                    {
                        op: ADD,
                        path: "/accessToken/claims/-",
                        value: {
                            name: "additionalRoles",
                            value: [
                                "accountant",
                                "manager"
                            ]
                        }
                    }
                ]
            };
        }
        resp.statusCode = 200;
        resp.setJsonPayload(respBody.toJson());

        return resp;   
    }   

    resource function post preIssueAccessTokenInsertUserID(http:Request req) returns http:Response|error? {
        
        ActionSuccessResponse respBody;
        http:Response resp = new;
        log:printInfo("Request Received to Insert UserID to the JWT access token");
        json requestPayload = <json> check req.getJsonPayload();
        log:printInfo(requestPayload.toString());
        
        // Extract user information from the request payload
        string userID = check getUserIdFromRequest(requestPayload);
        log:printInfo("Processing UserID: " + userID);
        
        // Check if userID already exists in the token
        string? existingUserID = check getAccessTokenClaim(requestPayload, "userID");
        string? existingSub = check getAccessTokenClaim(requestPayload, "sub");
        
        Operation[] operations = [];
        
        // Only add userID if it doesn't already exist
        if existingUserID == null {
            operations.push({
                op: ADD,
                path: "/accessToken/claims/-",
                value: {
                    name: "userID",
                    value: userID
                }
            });
            log:printInfo("Adding userID to token: " + userID);
        } else {
            log:printInfo("UserID already exists in token: " + existingUserID + ", skipping addition");
        }
        
        // Only add sub claim if it doesn't already exist
        if existingSub == null {
            operations.push({
                op: ADD,
                path: "/accessToken/claims/-",
                value: {
                    name: "sub",
                    value: userID
                }
            });
            log:printInfo("Adding sub claim to token: " + userID);
        } else {
            log:printInfo("Sub claim already exists in token: " + existingSub + ", skipping addition");
        }
        
        // Add some custom dummy claims
        operations.push({
            op: ADD,
            path: "/accessToken/claims/-",
            value: {
                name: "custom_app_id",
                value: "APP_12345"
            }
        });
        
        operations.push({
            op: ADD,
            path: "/accessToken/claims/-",
            value: {
                name: "tenant_id",
                value: "tenant_demo_001"
            }
        });
        
        respBody = {
            "actionStatus": SUCCESS,
            "operations": operations
        };
        
        // Add custom headers
        resp.setHeader("X-Custom-Action", "UserID-Insertion");
        resp.setHeader("X-Processing-Time", generateTimestamp());
        resp.setHeader("X-Token-Version", "v2.1");
        resp.setHeader("X-Auth-Provider", "Ballerina-Action-Service");
        resp.setHeader("X-Operations-Count", operations.length().toString());
        
        resp.statusCode = 200;
        resp.setJsonPayload(respBody.toJson());

        return resp;   
    }

    resource function post preIssueAccessTokenError(http:Request req) returns http:Response|error? {
        
        log:printInfo("Request Received to simulate an error");
        ActionFailedResponse respBody = {
            actionStatus: ERROR,
            'error: "access_denied",
            error_description: "The user is not authorized to access the resource"
        };
        http:Response resp = new;
        resp.statusCode = 400;
        resp.setJsonPayload(respBody.toJson());

        return resp;
    }
}

// Function to get the email value from the claims
function getAccessTokenClaim(json requestPayload, string claimName) returns string|error? {
    json? claimsJson = check requestPayload.toJson().event.accessToken.claims;

    if claimsJson is json[] {
        foreach json claim in claimsJson {
            if claim.name == claimName {
                return (check claim.value).toString();
            }
        }
    }
    return null;
}

// Function to extract userID from the request payload
function getUserIdFromRequest(json requestPayload) returns string|error {
    // Try to get userID from different possible locations in the request
    json|error userIdFromUser = requestPayload.toJson().event.request.user.id;
    json|error usernameFromUser = requestPayload.toJson().event.request.user.username;
    json|error subjectFromClaims = requestPayload.toJson().event.request.user.sub;
    
    if userIdFromUser is json && userIdFromUser != null {
        return userIdFromUser.toString();
    } else if subjectFromClaims is json && subjectFromClaims != null {
        return subjectFromClaims.toString();
    } else if usernameFromUser is json && usernameFromUser != null {
        return usernameFromUser.toString();
    } else {
        // Try to extract from existing access token claims as fallback
        string? existingUserId = check getAccessTokenClaim(requestPayload, "userID");
        if existingUserId != null {
            return existingUserId;
        }
        
        string? existingSub = check getAccessTokenClaim(requestPayload, "sub");
        if existingSub != null {
            return existingSub;
        }
        
        // Generate a default userID if not found anywhere
        return "default_user_" + generateTimestamp();
    }
}

// Function to generate timestamp for unique identifiers
function generateTimestamp() returns string {
    // Using current time representation
    return "1729531200000"; // Example timestamp
}
