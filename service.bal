import ballerina/http;
import ballerina/jwt;
import ballerina/log;
import ballerina/time;
import ballerina/regex;

// Configuration
configurable boolean enabledDebugLog = false;
configurable string expectedIssuer = "wso2";
configurable string? expectedAudience = "DNrwSQcWhrfAImyLp0m_CjigT9Ma";
configurable string? jwksUrl = "https://dev.api.asgardeo.io/t/nilukadevspecialusecases/oauth2/jwks";

// JWT Validator class
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
                self.jwksClient = check new(jwksEndpoint, {timeout: 30});
                log:printInfo(string `JWKS client initialized: ${jwksEndpoint}`);
            } on fail error err {
                log:printError(string `JWKS client initialization failed: ${err.message()}`);
                self.jwksClient = ();
            }
        } else {
            self.jwksClient = ();
        }
    }
    
    function validateJWT(string jwtToken) returns jwt:Payload|error {
        do {
            if !self.isValidJWTFormat(jwtToken) {
                return error("Invalid JWT format");
            }
            
            [jwt:Header, jwt:Payload] [header, payload] = check jwt:decode(jwtToken);
            
            string? algorithm = header.alg;
            if algorithm is () || !self.isSupportedAlgorithm(algorithm) {
                return error(string `Unsupported algorithm: ${algorithm ?: "none"}`);
            }
            
            jwt:ValidatorConfig validatorConfig = check self.createValidatorConfig();
            jwt:Payload validatedPayload = check jwt:validate(jwtToken, validatorConfig);
            check self.validateCustomClaims(validatedPayload);
            
            log:printInfo("JWT validation successful");
            return validatedPayload;
            
        } on fail error err {
            log:printError(string `JWT validation failed: ${err.message()}`);
            return err;
        }
    }
    
    private function createValidatorConfig() returns jwt:ValidatorConfig|error {
        jwt:ValidatorConfig config = {
            issuer: self.expectedIssuer,
            clockSkew: 60
        };
        
        if self.expectedAudience != "" {
            config.audience = [self.expectedAudience];
        }
        
        if self.jwksUrl is string {
            config.signatureConfig = {
                jwksConfig: {
                    url: <string>self.jwksUrl
                }
            };
        }
        
        return config;
    }
    
    private function isValidJWTFormat(string jwtToken) returns boolean {
        string[] parts = regex:split(jwtToken, "\\.");
        return parts.length() == 3 && parts[0] != "" && parts[1] != "" && parts[2] != "";
    }
    
    private function isSupportedAlgorithm(string algorithm) returns boolean {
        return algorithm == "RS256" || algorithm == "HS256" || algorithm == "ES256" || algorithm == "RS512";
    }
    
    private function validateCustomClaims(jwt:Payload payload) returns error? {
        anydata userId = payload.get("userId");
        if userId is () {
            return error("Missing required 'userId' claim in JWT");
        }
        
        anydata issuer = payload.get("iss");
        if issuer is string && issuer != self.expectedIssuer {
            return error(string `Invalid issuer. Expected: ${self.expectedIssuer}, Found: ${issuer}`);
        }
        
        anydata exp = payload.get("exp");
        if exp is int {
            decimal currentTime = <decimal>time:utcNow()[0];
            if <decimal>exp < currentTime {
                return error("JWT token has expired");
            }
        }
        
        anydata nbf = payload.get("nbf");
        if nbf is int {
            decimal currentTime = <decimal>time:utcNow()[0];
            if <decimal>nbf > currentTime {
                return error("JWT token is not yet valid");
            }
        }
        
        return;
    }
    
    function extractUserId(jwt:Payload payload) returns string|error {
        anydata userId = payload.get("userId");
        if userId is string {
            return userId;
        }
        return error("Unable to extract userId from JWT payload");
    }
    
    function testJWKSConnectivity() returns json|error {
        if self.jwksClient is () {
            return error("JWKS client not configured");
        }
        
        http:Client jwksClient = <http:Client>self.jwksClient;
        json response = check jwksClient->get("");
        return response;
    }
}

final JWTValidator jwtValidator = new(expectedIssuer, expectedAudience, jwksUrl);

function extractJWTFromParams(RequestParams[] reqParams) returns string|error {
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

service / on new http:Listener(9092) {

    resource function get health() returns json {
        return {
            status: "UP",
            service: "asgardeo-e2e-special-cases",
            version: "1.0.0",
            timestamp: time:utcNow()[0],
            jwksConfigured: jwksUrl is string,
            expectedIssuer: expectedIssuer,
            expectedAudience: expectedAudience
        };
    }

    resource function get test\-jwks() returns json {
        if jwksUrl is () {
            return {
                status: "JWKS_NOT_CONFIGURED",
                message: "JWKS URL not provided in configuration"
            };
        }
        
        json|error connectivityTest = jwtValidator.testJWKSConnectivity();
        if connectivityTest is json {
            int keysCount = 0;
            if connectivityTest is map<json> {
                json keysValue = connectivityTest["keys"];
                if keysValue is json[] {
                    keysCount = keysValue.length();
                }
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
                error: connectivityTest.message(),
                message: "Failed to connect to JWKS endpoint"
            };
        }
    }

    resource function post .(RequestBody payload) returns http:Ok|http:BadRequest {
        do {
            if enabledDebugLog {
                log:printInfo(string `Received request: ${payload.toJsonString()}`);
            }
            
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
            
            string jwtToken = check extractJWTFromParams(requestParams);
            
            if enabledDebugLog {
                log:printInfo("Extracted JWT token for validation");
            }
            
            jwt:Payload|error validationResult = jwtValidator.validateJWT(jwtToken);
            
            if validationResult is jwt:Payload {
                string userId = check jwtValidator.extractUserId(validationResult);
                
                if enabledDebugLog {
                    log:printInfo(string `JWT validation successful for userId: ${userId}`);
                }
                
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
                string errorMsg = validationResult.message();
                log:printError(string `JWT validation failed: ${errorMsg}`);
                
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
            log:printError(string `${msg}: ${err.message()}`);
            
            return <http:BadRequest>{
                body: {
                    actionStatus: "ERROR",
                    errorMessage: msg,
                    errorDescription: err.message()
                }
            };
        }
    }
}
