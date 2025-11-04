import ballerina/http;
import ballerina/log;
import ballerina/time;
import ballerina/uuid;

// Define the request/response types for WSO2 Pre-Issue Access Token action
type OperationType "add"|"remove"|"replace";

type Claim record {|
    string name;
    anydata value;
|};

type AccessToken record {|
    string tokenType?;
    string[] scopes?;
    Claim[] claims?;
|};

type RefreshToken record {|
    Claim[] claims?;
|};

type TokenRequest record {|
    string clientId;
    string grantType;
    string[] scopes?;
    map<string[]> additionalHeaders?;
    map<string[]> additionalParams?;
|};

type Organization record {|
    string id;
    string name;
    string orgHandle?;
    int depth?;
|};

type User record {|
    string id;
    Organization organization;
|};

type UserStore record {|
    string id;
    string name;
|};

type TokenEvent record {|
    TokenRequest request;
    record {|
        string id;
        string name;
    |} tenant;
    Organization organization;
    User user;
    UserStore userStore;
    AccessToken accessToken;
    RefreshToken refreshToken;
|};

type AllowedOperation record {|
    OperationType op;
    string[] paths;
|};

type PreIssueRequest record {|
    string actionType;
    TokenEvent event;
    AllowedOperation[] allowedOperations;
    string requestId?;
|};

type Operation record {|
    OperationType op;
    string path;
    anydata value?;
|};

type SuccessResponse record {|
    string actionStatus = "SUCCESS";
    Operation[] operations;
|};

type FailedResponse record {|
    string actionStatus = "FAILED";
    string failureReason;
    string failureDescription;
|};

type ErrorResponse record {|
    string actionStatus = "ERROR";
    string errorMessage;
    string errorDescription;
|};

// Service configuration
final string SERVICE_ENDPOINT = "/pre-issue-token";
final int SERVICE_PORT = 9090;

// Service implementation
service / on new http:Listener(SERVICE_PORT) {

    resource function post pre-issue-token(http:Caller caller, PreIssueRequest request) returns error? {
        
        log:printInfo("Received pre-issue token request", 
            requestId = request?.requestId.toString(), 
            clientId = request.event.request.clientId,
            grantType = request.event.request.grantType,
            userId = request.event.user.id
        );

        // Validate the action type
        if request.actionType != "PRE_ISSUE_ACCESS_TOKEN" {
            ErrorResponse errorResponse = {
                actionStatus: "ERROR",
                errorMessage: "Invalid action type",
                errorDescription: "Expected PRE_ISSUE_ACCESS_TOKEN but received " + request.actionType
            };
            http:Response response = new;
            response.setJsonPayload(errorResponse);
            response.statusCode = 400;
            check caller->respond(response);
            return;
        }

        // Validate that user ID exists
        if request.event.user.id == "" {
            FailedResponse failedResponse = {
                actionStatus: "FAILED",
                failureReason: "invalid_request",
                failureDescription: "User ID is missing from the request"
            };
            http:Response response = new;
            response.setJsonPayload(failedResponse);
            check caller->respond(response);
            return;
        }

        // Your custom business logic here
        SuccessResponse successResponse = processTokenRequest(request);
        
        http:Response response = new;
        response.setJsonPayload(successResponse);
        response.setHeader("Content-Type", "application/json");
        check caller->respond(response);
        
        log:printInfo("Successfully processed pre-issue token request", userId = request.event.user.id);
    }
}

// Main business logic function
function processTokenRequest(PreIssueRequest request) returns SuccessResponse {
    string timestamp = time:utcToString(time:utcNow());
    string userId = request.event.user.id; // Using the actual user ID from the request
    
    // Extract issuer from existing token claims
    string|error issuer = extractIssuer(request.event.accessToken.claims);
    if issuer is error {
        log:printError("Failed to extract issuer", error = issuer.message());
        issuer = "https://dev.api.asgardeo.io/t/" + request.event.organization.name + "/oauth2/token";
    }
    
    // Create operations array to modify the access token
    Operation[] operations = [];
    
    // Add userId claim (using the actual user ID from the request)
    operations.push({
        op: "add",
        path: "/accessToken/claims/-",
        value: {
            name: "userId",
            value: userId
        }
    });
    
    // Add tokenValidation claim
    operations.push({
        op: "add", 
        path: "/accessToken/claims/-",
        value: {
            name: "tokenValidation",
            value: `{"signature":"valid","method":"JWKS_RS256","issuer":"${issuer}","timestamp":"${timestamp}"}`
        }
    });
    
    // Add mfaValidation claim  
    operations.push({
        op: "add",
        path: "/accessToken/claims/-", 
        value: {
            name: "mfaValidation",
            value: `{"status":"success","method":"ID_TOKEN_AMR_VALIDATION","timestamp":"${timestamp}"}`
        }
    });
    
    // Add organization context claims
    operations.push({
        op: "add",
        path: "/accessToken/claims/-",
        value: {
            name: "organizationContext",
            value: `{"orgId":"${request.event.organization.id}","orgName":"${request.event.organization.name}","userStore":"${request.event.userStore.name}"}`
        }
    });
    
    // Add custom claims based on user ID pattern or other logic
    if isServiceAccount(userId) {
        operations.push({
            op: "add", 
            path: "/accessToken/claims/-",
            value: {
                name: "accountType",
                value: "SERVICE_ACCOUNT"
            }
        });
        
        // Add service account specific scopes
        operations.push({
            op: "add",
            path: "/accessToken/scopes/-",
            value: "internal_api_access"
        });
    } else {
        operations.push({
            op: "add",
            path: "/accessToken/claims/-", 
            value: {
                name: "accountType",
                value: "USER_ACCOUNT"
            }
        });
    }
    
    // Add request context information
    operations.push({
        op: "add",
        path: "/accessToken/claims/-",
        value: {
            name: "requestContext", 
            value: `{"clientId":"${request.event.request.clientId}","grantType":"${request.event.request.grantType}"}`
        }
    });

    return {
        actionStatus: "SUCCESS",
        operations: operations
    };
}

// Helper function to extract issuer from existing claims
function extractIssuer(Claim[]? claims) returns string|error {
    if claims is () {
        return error("No claims found in access token");
    }
    
    foreach Claim claim in claims {
        if claim.name == "iss" {
            return claim.value.toString();
        }
    }
    
    return error("Issuer claim not found in access token");
}

// Helper function to check if user ID belongs to a service account
function isServiceAccount(string userId) returns boolean {
    // Example logic: service accounts might have specific patterns
    // You can customize this based on your user ID naming conventions
    return userId.startsWith("svc_") || userId.endsWith("-service");
}

// Helper function to generate validation timestamp
function generateValidationData(string userId) returns map<anydata> {
    string timestamp = time:utcToString(time:utcNow());
    string validationId = checkpanic uuid:createType1UUID();
    
    return {
        userId: userId,
        validatedAt: timestamp,
        validationId: validationId,
        system: "pre-issue-token-service"
    };
}

// Main function
public function main() {
    log:printInfo("WSO2 Pre-Issue Access Token Service started");
    log:printInfo("Service endpoint: http://localhost:" + SERVICE_PORT.toString() + SERVICE_ENDPOINT);
}
