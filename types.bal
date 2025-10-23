// Simplified types for Choreo deployment - SPA Authentication Extension API

// Complete types for Pre-Issue Access Token action with proper optionality
type RequestParams record {
    string? name;
    string[]? value;
};

type Request record {
    string? grantType;
    string? clientId;
    string[]? scopes;
    RequestParams[]? additionalParams;
};

type User record {
    string? id;
    string? username;
    string? email;
};

type Organization record {
    string? id;
    string? name;
};

type Tenant record {
    string? id;
    string? name;
};

type UserStore record {
    string? id;
    string? name;
};

type AccessTokenClaims record {
    string? name;
    string|int|boolean|string[]? value;
};

// AccessToken type with all fields properly optional
type AccessToken record {
    AccessTokenClaims[]? claims?;
    string[]? scopes?;
};

type Event record {
    Request? request;
    Tenant? tenant;
    User? user;
    Organization? organization;
    UserStore? userStore;
    AccessToken? accessToken;
};

type RequestBody record {
    string? requestId;
    ActionType? actionType;
    Event? event;
};

// Operation Types for Response
type OperationValue record {
    string name;
    string value;
};

type Operation record {
    string op;
    string path;
    OperationValue value;
};

// Action and Status Enums
enum ActionType {
    PRE_ISSUE_ACCESS_TOKEN
}

enum ActionStatus {
    SUCCESS,
    FAILED,
    ERROR
}
