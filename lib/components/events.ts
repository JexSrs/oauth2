export enum Events {
    INVALID_REDIRECT_URI = 'invalid-redirect-uri',
    INVALID_SCOPES = 'invalid-scopes',
    INVALID_CLIENT = 'invalid-client',
    INVALID_REQUEST = 'invalid-request',
    ACCESS_DENIED = 'access-denied',
    UNSUPPORTED_RESPONSE_TYPE = 'unsupported-response-type',
    UNSUPPORTED_GRANT_TYPE = 'unsupported-grant-type',
    REJECTED_FLOW = 'rejected-flow',

    FAILED_TOKEN_SAVE = 'failed-token-save',
    FAILED_AUTHORIZATION_CODE_SAVE = 'failed-authorization-code-save',
    FAILED_DEVICE_CODE_SAVE = 'failed-device-code-save',

    INVALID_PKCE = 'invalid-pkce',
    INVALID_AUTHORIZATION_CODE_TOKEN_JWT = 'invalid-authorization-code-token-jwt',
    INVALID_AUTHORIZATION_CODE_TOKEN_CLIENT = 'invalid-authorization-code-token-client',
    INVALID_AUTHORIZATION_CODE_TOKEN_DB = 'invalid-authorization-code-token-db',

    SLOW_DOWN = 'slow-down',
    INVALID_DEVICE_CODE = 'invalid-device-code',
    EXPIRED_DEVICE_CODE = 'expired-device-code',
    REQUEST_PENDING = 'request-pending',

    INVALID_USER = 'invalid-user',

    INVALID_REFRESH_TOKEN_JWT = 'invalid-refresh-token-jwt',
    INVALID_REFRESH_TOKEN_NOT = 'invalid-refresh-token-not',
    INVALID_REFRESH_TOKEN_SCOPES = 'invalid-refresh-token-scopes',
    INVALID_REFRESH_TOKEN_CLIENT = 'invalid-refresh-token-client',
    INVALID_REFRESH_TOKEN_DB = 'invalid-refresh-token-db',

    AUTHENTICATION_MISSING_TOKEN = 'authentication-missing-token',
    AUTHENTICATION_INVALID_TOKEN_JWT = 'authentication-invalid-token-jwt',
    AUTHENTICATION_INVALID_TOKEN_NOT = 'authentication-invalid-token-db',
    AUTHENTICATION_INVALID_TOKEN_DB = 'authentication-invalid-token-db',
    AUTHENTICATION_INVALID_TOKEN_SCOPES = 'authentication-invalid-token-scopes',
}