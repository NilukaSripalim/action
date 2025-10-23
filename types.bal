// Simplified types for Choreo deployment - SPA Authentication Extension API

// Updated types based on actual Asgardeo webhook payload - using open records
type RequestParams record {
    string? name;
    string[]? value;
};

type Request record {
    string? grantType;
    string? clientId;
    string[]? scopes;
    RequestParams[]? additionalParams;
    RequestParams[]? additionalHeaders;
};

type User record {
    string? id;
    Organization? organization;
};

type Organization record {
    string? id;
    string? name;
    string? orgHandle;
    int? depth;
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

type AccessToken record {
    string? tokenType;
    AccessTokenClaims[]? claims;
};

type RefreshToken record {
    AccessTokenClaims[]? claims;
};

type OperationPaths record {
    string? op;
    string[]? paths;
};

type Event record {
    Request? request;
    Tenant? tenant;
    User? user;
    Organization? organization;
    UserStore? userStore;
    AccessToken? accessToken;
    RefreshToken? refreshToken;
};

type RequestBody record {
    string? requestId;
    ActionType? actionType;
    Event? event;
    OperationPaths[]? allowedOperations;
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
