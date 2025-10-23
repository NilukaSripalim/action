import ballerina/auth;
import ballerina/http;
import ballerina/jwt;
import ballerina/log;

configurable boolean enabledDebugLog = false;
configurable string certFilePath = ?;
auth:FileUserStoreConfig fileUserStoreConfig = {};

function extractJWT(RequestParams[] requestParams) returns string|error {
    foreach RequestParams param in requestParams {
        if param.name == "jwt" && param.value is string[] && param.value.length() > 0 {
            return param.value[0];
        }
    }
    return error("JWT parameter not found");
}

@http:ServiceConfig {
    auth: [
        {
            fileUserStoreConfig: fileUserStoreConfig
        }
    ]
}
isolated service / on new http:Listener(9092) {

    isolated resource function post .(RequestBody payload) returns SuccessResponseOk|ErrorResponseBadRequest|ErrorResponseInternalServerError|error {
        do {
            log:printDebug(payload.actionType.toJsonString());
            if payload.actionType == PRE_ISSUE_ACCESS_TOKEN {
                RequestParams[]? requestParams = payload.event?.request?.additionalParams;
                if requestParams is () {
                    string msg = "Required parameters for JWT validation are missing";
                    log:printDebug(msg);
                    return <ErrorResponseBadRequest>{body: {actionStatus: ERROR, errorMessage: msg, errorDescription: "userId & other params are mandatory to proceed the request"}};
                }
                log:printDebug(requestParams.toJsonString());
                jwt:ValidatorConfig validatorConfig = {
                    issuer: "wso2",
                    clockSkew: 60,
                    signatureConfig: {
                        certFile: certFilePath
                    }
                };
                string jwt = check extractJWT(requestParams);
                jwt:Payload|error result = jwt:validate(jwt, validatorConfig);
                if result is jwt:Payload {
                    [jwt:Header, jwt:Payload] [_, jwtpayload] = check jwt:decode(jwt);
                    return <SuccessResponseOk>{
                        body: {
                            actionStatus: SUCCESS,
                            operations: [
                                {
                                    op: "add",
                                    path: "/accessToken/claims/-",
                                    value: {
                                        name: "userId",
                                        value: jwtpayload.get("userId").toString()
                                    }
                                }
                            ]
                        }
                    };
                }
            }
            return <ErrorResponseBadRequest>{body: {actionStatus: ERROR, errorMessage: "Invalid action type", errorDescription: "Support is available only for the PRE_ISSUE_ACCESS_TOKEN action type"}};
        } on fail error err {
            string msg = "Something went wrong while extracting additional parameters";
            log:printDebug(string `${msg}: ${err.message()}`);
            return <ErrorResponseBadRequest>{body: {actionStatus: ERROR, errorMessage: msg, errorDescription: err.detail().toString()}};
        }
    }

}
