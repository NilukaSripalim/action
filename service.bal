import ballerina/http;
import ballerina/log;
import ballerina/time;

// Service configuration
final string SERVICE_ENDPOINT = "/pre-issue-token";
final int SERVICE_PORT = 9090;

// Service implementation
service / on new http:Listener(SERVICE_PORT) {

    resource function post pre-issue-token(http:Caller caller, RequestBody request) returns error? {
        log:printInfo("Received pre-issue token request");
        
        // Simple success response with basic operations
        SuccessResponse successResponse = {
            actionStatus: SUCCESS,
            operations: [
                {
                    op: "add",
                    path: "/accessToken/claims/-",
                    value: {
                        name: "userId",
                        value: request?.event?.user?.id ?: "unknown"
                    }
                }
            ]
        };
        
        http:Response response = new;
        response.setJsonPayload(successResponse.toJson());
        check caller->respond(response);
    }
}

public function main() {
    log:printInfo("WSO2 Pre-Issue Access Token Service started");
}
