// Enums
public enum ActionTypes {
    PRE_ISSUE_ACCESS_TOKEN
}

public enum ActionStatus {
    SUCCESS,
    FAILED,
    ERROR
}

// Request types
public type RequestBody record {
    string requestId?;
    ActionTypes actionType;
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
    map<string[]> additionalHeaders?;
    map<string[]> additionalParams?;
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
    RefreshTokenClaims[] claims?;
};

// Claims can have different value types per WSO2 spec
public type AccessTokenClaims record {
    string name?;
    string|int|boolean|string[] value?;
};

// Refresh token claims are similar but typically simpler
public type RefreshTokenClaims record {
    string name?;
    string|int|boolean value?;
};

// Operation types - Updated to support flexible value types
public type Operations record {
    string op;
    string path;
    ClaimValue value;
};

// Flexible claim value type for operations
public type ClaimValue record {
    string name;
    string|int|boolean|string[] value;
};

public type AllowedOperation record {
    string op?;
    string[] paths?;
};

// Response types
// SUCCESS response - returns operations array
public type SuccessResponse record {|
    ActionStatus actionStatus;
    Operations[] operations;
|};

// FAILED response - uses failureReason and failureDescription
// This is returned when business logic determines token should not be issued
public type FailedResponse record {|
    ActionStatus actionStatus;
    string failureReason;        // Maps to OAuth2 'error' field
    string failureDescription;   // Maps to OAuth2 'error_description' field
|};

// ERROR response - uses errorMessage and errorDescription
// This is returned when there's a processing error in your service
public type ErrorResponse record {|
    ActionStatus actionStatus;
    string errorMessage;
    string errorDescription;
|};
