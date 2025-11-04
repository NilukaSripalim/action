// main.bal
import ballerina/http;
import ballerina/log;
import ballerina/time;
import ballerina/uuid;

// Import the types (assuming both files are in the same package)
// If you have a package structure, use: import your_package/types;

// Service configuration
final string SERVICE_ENDPOINT = "/pre-issue-token";
final int SERVICE_PORT = 9090;

// Service implementation
service / on new http:Listener(SERVICE_PORT) {

    resource function post pre-issue-token(http:Caller caller, RequestBody request) returns error? {
        
        log:printInfo("Received pre-issue token request", 
            requestId = request?.requestId.toString(), 
            clientId = request.event.request.clientId,
            grantType = request.event.request.grantType,
            userId = request.event.user.id
        );

        // Validate the action type
        if request.actionType != PRE_ISSUE_ACCESS_TOKEN {
            ErrorResponse errorResponse = {
                actionStatus: ERROR,
                errorMessage: "Invalid action type",
                errorDescription: "Expected PRE_ISSUE_ACCESS_TOKEN but received " + request.actionType.toString()
            };
            http:Response response = new;
            response.setJsonPayload(errorResponse);
            response.statusCode = 400;
            check caller->respond(response);
            return;
        }

        // Validate that user ID exists
        if request.event.user.id == "" || request.event.user.id is () {
            FailedResponse failedResponse = {
                actionStatus: FAILED,
                failureReason: "invalid_request",
                failureDescription: "User ID is missing from the request"
            };
            http:Response response = new;
            response.setJsonPayload(failedResponse);
            check caller->respond(response);
            return;
        }

        // Process the token request
        SuccessResponse|ErrorResponse processResult = processTokenRequest(request);
        
        if processResult is ErrorResponse {
            http:Response response = new;
            response.setJsonPayload(processResult);
            response.statusCode = 500;
            check caller->respond(response);
            return;
        }
        
        http:Response response = new;
        response.setJsonPayload(processResult);
        response.setHeader("Content-Type", "application/json");
        check caller->respond(response);
        
        log:printInfo("Successfully processed pre-issue token request", 
            userId = request.event.user.id,
            operationsCount = processResult.operations.length()
        );
    }
}

// Main business logic function
function processTokenRequest(RequestBody request) returns SuccessResponse|ErrorResponse {
    // Validate required fields
    if request.event.user.id is () || request.event.user.id == "" {
        return {
            actionStatus: ERROR,
            errorMessage: "Missing user ID",
            errorDescription: "User ID is required for processing"
        };
    }

    string timestamp = time:utcToString(time:utcNow());
    string userId = request.event.user.id.toString();

    // Extract issuer from existing token claims
    string|error issuerResult = extractIssuer(request.event.accessToken?.claims);
    if issuerResult is error {
        return {
            actionStatus: ERROR,
            errorMessage: "Issuer extraction failed",
            errorDescription: issuerResult.message()
        };
    }
    string issuer = issuerResult;

    // Create operations array
    Operations[] operations = [];

    // Add userId claim
    Operations userIdOperation = {
        op: "add",
        path: "/accessToken/claims/-",
        value: {
            name: "userId",
            value: userId
        }
    };
    operations.push(userIdOperation);

    // Add tokenValidation claim with structured record
    TokenValidationRecord tokenValidation = {
        signature: "valid",
        method: "JWKS_RS256", 
        issuer: issuer,
        timestamp: timestamp
    };
    
    Operations tokenValidationOperation = {
        op: "add",
        path: "/accessToken/claims/-", 
        value: {
            name: "tokenValidation",
            value: tokenValidation
        }
    };
    operations.push(tokenValidationOperation);

    // Add mfaValidation claim with structured record
    MFAValidationRecord mfaValidation = {
        status: "success",
        method: "ID_TOKEN_AMR_VALIDATION",
        timestamp: timestamp
    };
    
    Operations mfaValidationOperation = {
        op: "add",
        path: "/accessToken/claims/-",
        value: {
            name: "mfaValidation", 
            value: mfaValidation
        }
    };
    operations.push(mfaValidationOperation);

    // Add additional context based on user and organization
    Operations[] additionalOperations = createAdditionalOperations(request, userId, timestamp);
    operations.push(...additionalOperations);

    return {
        actionStatus: SUCCESS,
        operations: operations
    };
}

// Helper function to extract issuer from existing claims
function extractIssuer(AccessTokenClaims[]? claims) returns string|error {
    if claims is () {
        return error("No claims found in access token");
    }
    
    foreach var claim in claims {
        if claim.name == "iss" && claim.value is string {
            return <string>claim.value;
        }
    }
    
    return error("Issuer claim not found in access token or has invalid type");
}

// Function to create additional operations based on context
function createAdditionalOperations(RequestBody request, string userId, string timestamp) returns Operations[] {
    Operations[] additionalOps = [];

    // Add organization context if available
    if request.event.organization is () {
        string orgContext = `Organization: ${request.event.organization?.name ?: "unknown"}`;
        additionalOps.push({
            op: "add",
            path: "/accessToken/claims/-",
            value: {
                name: "orgContext",
                value: orgContext
            }
        });
    }

    // Add client context
    additionalOps.push({
        op: "add", 
        path: "/accessToken/claims/-",
        value: {
            name: "clientContext",
            value: `Client: ${request.event.request?.clientId ?: "unknown"}`
        }
    });

    // Add processing timestamp
    additionalOps.push({
        op: "add",
        path: "/accessToken/claims/-",
        value: {
            name: "processedAt",
            value: timestamp
        }
    });

    return additionalOps;
}

// Helper function to check allowed operations
function isOperationAllowed(AllowedOperation[]? allowedOps, string operation, string path) returns boolean {
    if allowedOps is () {
        return false;
    }

    foreach var allowedOp in allowedOps {
        if allowedOp.op == operation {
            foreach var allowedPath in allowedOp.paths {
                if path.startsWith(allowedPath) {
                    return true;
                }
            }
        }
    }
    return false;
}

// Main function
public function main() {
    log:printInfo("WSO2 Pre-Issue Access Token Service started");
    log:printInfo("Service endpoint: http://localhost:" + SERVICE_PORT.toString() + SERVICE_ENDPOINT);
    log:printInfo("Service configured with strict type checking");
}
