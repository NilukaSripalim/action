import ballerina/http;

// Enums
public enum ActionTypes {
    PRE_ISSUE_ACCESS_TOKEN
}

public enum ActionStatus {
    SUCCESS,
    FAILED,
    ERROR
}

// Response records - separate for each status
public type SuccessResponse record {|
    readonly & http:Ok;
    ResponseBody body;
|};

public type ErrorResponse record {|
    readonly & http:BadRequest;
    ResponseBody body;
|};

public type InternalErrorResponse record {|
    readonly & http:InternalServerError;
    ResponseBody body;
|};

public type ResponseBody record {
    ActionStatus actionStatus;
    Operations[] operations?;
    string failureReason?;
    string failureDescription?;
    string errorMessage?;
    string errorDescription?;
};

// Request types
public type RequestBody record {
    string requestId?;
    ActionTypes actionType?;
    Event event?;
    AllowedOperation[] allowedOperations?;
};

public type Event record {
    Request request?;
    Tenant tenant?;
    User user?;
    Organization organization?;
    UserStore userStore?;
    AccessToken accessToken?;
    RefreshToken refreshToken?;
};

public type Request record {
    string grantType?;
    string clientId?;
    string[] scopes?;
    RequestHeaders[] additionalHeaders?;
    RequestParams[] additionalParams?;
};

public type RequestParams record {
    string name?;
    string[] value?;
};

public type RequestHeaders record {
    string name?;
    string[] value?;
};

public type User record {
    string id?;
    Organization organization?;
};

public type Organization record {
    string id?;
    string name?;
    string orgHandle?;
    int depth?;
};

public type Tenant record {
    string id?;
    string name?;
};

public type UserStore record {
    string id?;
    string name?;
};

public type AccessToken record {
    string tokenType?;
    AccessTokenClaims[] claims?;
    string[] scopes?;
};

public type RefreshToken record {
    AccessTokenClaims[] claims?;
};

public type AccessTokenClaims record {
    string name?;
    string|int|boolean|string[] value?;
};

// Operation types
public type Operations record {
    string op;
    string path;
    OperationValue value;
};

public type OperationValue record {
    string name;
    string value;
};

public type AllowedOperation record {
    string op?;
    string[] paths?;
};
