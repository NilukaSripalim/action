import ballerina/http;
import ballerina/jwt;
import ballerina/log;
import ballerina/time;
import ballerina/regex;

// Choreo-ready configuration with JWKS support
configurable boolean enabledDebugLog = false;
configurable string expectedIssuer = "wso2";
configurable string? expectedAudience = "DNrwSQcWhrfAImyLp0m_CjigT9Ma";
configurable string? jwksUrl = "https://dev.api.asgardeo.io/t/nilukadevspecialusecases/oauth2/jwks"; // JWKS endpoint URL for JWT signature validation

// JWT Validator with JWKS support - All in one class
class JWTValidator {
    private string expectedIssuer;
    private string expectedAudience;
    private string? jwksUrl;
    private http:Client? jwksClient;
    
    function init(string issuer = "wso2", string? audience = (), string? jwksEndpoint = ()) {
        self.expectedIssuer = issuer;
        self.expectedAudience = audience ?: "";
        self.jwksUrl = jwksEndpoint;
        
        if jwksEndpoint is string {
            do {
                self.jwksClient = check new(jwksEndpoint);
                log:printInfo(string `✅ JWKS client initialized: ${jwksEndpoint}`);
            } on fail error err {
                log:printError(string `❌ JWKS client initialization failed: ${err.message()}`);
                self.jwksClient = ();
            }
            }
        } else {
            self.jwksClient = ();
        }
    }
    
    // Main JWT validation function
    function validateJWT(string jwtToken) returns jwt:Payload|error {
        do {
            // Basic format validation
            if !self.isValidJWTFormat(jwtToken) {
                return error("Invalid JWT format - must have 3 parts separated by dots");
            }
            
            // Decode JWT to inspect header and payload
            [jwt:Header, jwt:Payload] [header, payload] = check jwt:decode(jwtToken);
            
            // Validate algorithm
            string? algorithm = header.alg;
            if algorithm is () || !self.isSupportedAlgorithm(algorithm) {
                return error(string `Unsupported algorithm: ${algorithm ?: "none"}`);
            }
            
            // Create validator config
            jwt:ValidatorConfig validatorConfig = check self.createValidatorConfig();
            
            // Validate JWT
            jwt:Payload validatedPayload = check jwt:validate(jwtToken, validatorConfig);
            
            // Custom claim validations
            check self.validateCustomClaims(validatedPayload);
            
            log:printInfo("✅ JWT validation successful");
            return validatedPayload;
            
        } on fail error err {
            log:printError(string `❌ JWT validation failed: ${err.message()}`);
            return err;
        }
    }
    
    // Create validator configuration
    private function createValidatorConfig() returns jwt:ValidatorConfig|error {
        jwt:ValidatorConfig config = {
            issuer: self.expectedIssuer,
            clockSkew: 60 // 60 seconds tolerance
        };
        
        // Add audience if specified
        if self.expectedAudience != "" {
            config.audience = [self.expectedAudience];
        }
        
        // Add JWKS configuration if available
        if self.jwksUrl is string {
            config.signatureConfig = {
                jwksConfig: {
                    url: <string>self.jwksUrl
                }
            };
        }
        
        return config;
    }
    
    // Validate JWT format
    private function isValidJWTFormat(string jwtToken) returns boolean {
        string[] parts = regex:split(jwtToken, "\\.");
        return parts.length() == 3 && parts[0] != "" && parts[1] != "" && parts[2] != "";
    }
    
    // Check supported algorithms
    private function isSupportedAlgorithm(string algorithm) returns boolean {
        return algorithm == "RS256" || algorithm == "HS256" || algorithm == "ES256" || algorithm == "RS512";
    }
    
    // Custom claim validations
    private function validateCustomClaims(jwt:Payload payload) returns error? {
        // Validate required userId claim
        anydata userId = payload.get("userId");
        if userId is () {
            return error("Missing required 'userId' claim in JWT");
        }
        
        // Validate issuer
        anydata issuer = payload.get("iss");
        if issuer is string && issuer != self.expectedIssuer {
            return error(string `Invalid issuer. Expected: ${self.expectedIssuer}, Found: ${issuer}`);
        }
        
        // Validate expiration
        anydata exp = payload.get("exp");
        if exp is int {
            int currentTime = <int>time:utcNow()[0];
            if exp < currentTime {
                return error("JWT token has expired");
            }
        }
        
        // Validate not before
        anydata nbf = payload.get("nbf");
        if nbf is int {
            int currentTime = <int>time:utcNow()[0];
            if nbf > currentTime {
                return error("JWT token is not yet valid");
            }
        }
        
        return;
    }
    
    // Extract userId from validated payload
    function extractUserId(jwt:Payload payload) returns string|error {
        anydata userId = payload.get("userId");
        if userId is string {
            return userId;
        }
        return error("Unable to extract userId from JWT payload");
    }
    
    // Test JWKS connectivity
    function testJWKSConnectivity() returns json|error {
        if self.jwksClient is () {
            return error("JWKS client not configured");
        }
        
        http:Client jwksClient = <http:Client>self.jwksClient;
        json response = check jwksClient->get("");
        return response;
    }
}

// Initialize JWT validator
final JWTValidator jwtValidator = new(expectedIssuer, expectedAudience, jwksUrl);

// Choreo-ready HTTP service
service / on new http:Listener(9092) {

    // Health check endpoint
    resource function get health() returns json {
        return {
            status: "UP",
            service: "spa-auth-ext-api",
            version: "1.0.0",
            timestamp: time:utcNow()[0],
            jwksConfigured: jwksUrl is string,
            expectedIssuer: expectedIssuer,
            expectedAudience: expectedAudience
        };
    }

    // Test JWKS connectivity
    resource function get test\-jwks() returns json {
        if jwksUrl is () {
            return {
                status: "JWKS_NOT_CONFIGURED",
                message: "JWKS URL not provided in configuration"
            };
        }
        
        json|error result = jwtValidator.testJWKSConnectivity();
        if result is json {
            anydata keysData = result["keys"];
            int keysCount = 0;
            if keysData is json[] {
                keysCount = keysData.length();
            }
            return {
                status: "JWKS_ACCESSIBLE",
                jwksUrl: jwksUrl,
                keysCount: keysCount,
                message: "JWKS endpoint is accessible"
            };
        } else {
            return {
                status: "JWKS_ERROR",
                jwksUrl: jwksUrl,
                error: result.message(),
                message: "Failed to connect to JWKS endpoint"
            };
        }
    }

    // Main webhook endpoint for Asgardeo Pre-Issue Access Token action
    resource function post .(RequestBody payload) returns http:Ok|http:BadRequest {
        do {
            if enabledDebugLog {
                log:printInfo(string `📥 Received request: ${payload.toJsonString()}`);
            }
            
            // Validate action type
            if payload.actionType != PRE_ISSUE_ACCESS_TOKEN {
                string msg = "Invalid action type";
                log:printError(string `${msg}: ${payload.actionType.toString()}`);
                return <http:BadRequest>{
                    body: {
                        actionStatus: "ERROR",
                        errorMessage: msg,
                        errorDescription: "Only PRE_ISSUE_ACCESS_TOKEN action type is supported"
                    }
                };
            }
            
            // Extract request parameters
            RequestParams[]? requestParams = payload.event?.request?.additionalParams;
            if requestParams is () {
                string msg = "Missing additional parameters";
                log:printError(msg);
                return <http:BadRequest>{
                    body: {
                        actionStatus: "ERROR",
                        errorMessage: msg,
                        errorDescription: "JWT parameter is required in additionalParams"
                    }
                };
            }
            
            // Extract JWT token
            string jwtToken = check self.extractJWT(requestParams);
            
            if enabledDebugLog {
                log:printInfo("🔍 Extracted JWT token for validation");
            }
            
            // Validate JWT
            jwt:Payload|error validationResult = jwtValidator.validateJWT(jwtToken);
            
            if validationResult is jwt:Payload {
                // Extract userId
                string userId = check jwtValidator.extractUserId(validationResult);
                
                if enabledDebugLog {
                    log:printInfo(string `✅ JWT validation successful for userId: ${userId}`);
                }
                
                // Return success response with userId claim
                return <http:Ok>{
                    body: {
                        actionStatus: "SUCCESS",
                        operations: [
                            {
                                op: "add",
                                path: "/accessToken/claims/-",
                                value: {
                                    name: "userId",
                                    value: userId
                                }
                            }
                        ]
                    }
                };
            } else {
                // Validation failed
                string errorMsg = validationResult.message();
                log:printError(string `❌ JWT validation failed: ${errorMsg}`);
                
                return <http:BadRequest>{
                    body: {
                        actionStatus: "ERROR",
                        errorMessage: "JWT validation failed",
                        errorDescription: errorMsg
                    }
                };
            }
            
        } on fail error err {
            string msg = "Internal server error during request processing";
            log:printError(string `💥 ${msg}: ${err.message()}`);
            
            return <http:BadRequest>{
                body: {
                    actionStatus: "ERROR",
                    errorMessage: msg,
                    errorDescription: err.message()
                }
            };
        }
    }

    // Utility function to extract JWT from request parameters
    private function extractJWT(RequestParams[] reqParams) returns string|error {
        foreach RequestParams param in reqParams {
            string? name = param.name;
            string[]? value = param.value;
            
            if name == "jwt" && value is string[] && value.length() > 0 {
                string jwtToken = value[0];
                if jwtToken.trim() == "" {
                    return error("JWT parameter is empty");
                }
                return jwtToken;
            }
        }
        
        return error("JWT parameter not found in request");
    }
}
