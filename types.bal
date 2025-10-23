import ballerina/http;

// Response types
type SuccessResponseOk record {|
    *http:Ok;
    SuccessResponseBody body;
|};

type SuccessResponseBody SuccessResponse|FailedResponse;

type SuccessResponse record {
    SUCCESS actionStatus;
    Operations[] operations;
};

type FailedResponse record {
    FAILED actionStatus;
    string failureReason;
    string failureDescription;
};

type ErrorResponseInternalServerError record {|
    *http:InternalServerError;
    ErrorResponse body;
|};

type ErrorResponseBadRequest record {|
    *http:BadRequest;
    ErrorResponse body;
|};

type ErrorResponse record {
    ERROR actionStatus?;
    string errorMessage?;
    string errorDescription?;
};

// Request types
type RequestBody record {
    string requestId?;
    PRE_ISSUE_ACCESS_TOKEN actionType?;
    Event event?;
    AllowedOperations allowedOperations?;
};

type Event record {
    Request request?;
    Tenant tenant?;
    User user?;
    Organization organization?;
    UserStore userStore?;
    AccessToken accessToken?;
    RefreshToken refreshToken?;
};

type Request record {
    string grantType?;
    string clientId?;
    string[] scopes?;
    RequestHeaders[] additionalHeaders?;
    RequestParams[] additionalParams?;
};

type RequestParams record {
    string name?;
    string[] value?;
};

type RequestHeaders record {
    string name?;
    string[] value?;
};

type User record {
    string id?;
    Organization organization?;
};

type Organization record {
    string id?;
    string name?;
    string orgHandle?;
    int depth?;
};

type Tenant record {
    string id?;
    string name?;
};

type UserStore record {
    string id?;
    string name?;
};

type AccessToken record {
    string tokenType?;
    AccessTokenClaims[] claims?;
    string[] scopes?;
};

type RefreshToken record {
    AccessTokenClaims[] claims?;
};

type AccessTokenClaims record {
    string name?;
    string|int|boolean|string[] value?;
};

// Operation types
type Operations record {
    string op;
    string path;
    OperationValue value;
};

type OperationValue record {
    string name;
    string value;
};

type AllowedOperations (addOperation|replaceOperation|removeOperation)[];

type AllowedOperation record {
    "add"|"replace"|"remove" op?;
    string[] paths?;
};

type addOperation AllowedOperation;
type replaceOperation AllowedOperation;
type removeOperation AllowedOperation;

// Enums
enum ActionTypes {
    PRE_ISSUE_ACCESS_TOKEN
}

enum ActionStatus {
    SUCCESS,
    FAILED,
    ERROR
}
