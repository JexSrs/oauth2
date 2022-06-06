export enum Events {
    // Authorization
    AUTHORIZATION_REDIRECT_URI_INVALID = 'authorization.redirect-uri.invalid',
    AUTHORIZATION_SCOPES_INVALID = 'authorization.scopes.invalid',
    AUTHORIZATION_EMBEDDED_WEBVIEW = 'authorization.embedded-web-view',
    AUTHORIZATION_RESPONSE_TYPE_UNSUPPORTED = 'authorization.response-type.unsupported',
    AUTHORIZATION_RESPONSE_TYPE_REJECT = 'authorization.response-type.reject',
    // Authorization flow "code"
    AUTHORIZATION_FLOWS_CODE_PKCE_INVALID = 'authorization.flows.code.pcke.invalid',
    AUTHORIZATION_FLOWS_CODE_SAVE_ERROR = 'authorization.flows.code.save.error',
    // Authorization flow "token"
    AUTHORIZATION_FLOWS_TOKEN_SAVE_ERROR = 'authorization.flows.token.save.error',


    // Token
    TOKEN_GRANT_TYPE_UNSUPPORTED = 'token.grant-type.unsupported',
    // Token flow "authorization_code"
    TOKEN_FLOWS_AUTHORIZATION_CODE_TOKEN_JWT_INVALID = 'token.flows.authorization-code.token.jwt-invalid',
    TOKEN_FLOWS_AUTHORIZATION_CODE_TOKEN_CLIENT_INVALID = 'token.flows.authorization-code.token.client-invalid',
    TOKEN_FLOWS_AUTHORIZATION_CODE_TOKEN_DB_INVALID = 'token.flows.authorization-code.token.db-invalid',
    TOKEN_FLOWS_AUTHORIZATION_CODE_CLIENT_INVALID = 'token.flows.authorization-code.client.invalid',
    TOKEN_FLOWS_AUTHORIZATION_CODE_REDIRECT_URI_INVALID = 'token.flows.authorization-code.redirect-uri.invalid',
    TOKEN_FLOWS_AUTHORIZATION_CODE_PKCE_INVALID = 'token.flows.authorization-code.pkce.invalid',
    TOKEN_FLOWS_AUTHORIZATION_CODE_SAVE_ERROR = 'token.flows.authorization-code.save.error',
    // Token flow "client_credentials"
    TOKEN_FLOWS_CLIENT_CREDENTIALS_SCOPES_INVALID = 'token.flows.client-credentials.scopes.invalid',
    TOKEN_FLOWS_CLIENT_CREDENTIALS_CLIENT_INVALID = 'token.flows.client-credentials.client.invalid',
    TOKEN_FLOWS_CLIENT_CREDENTIALS_SAVE_ERROR = 'token.flows.client-credentials.save.error',
    // Token flow "urn:ietf:params:oauth:grant-type:device_code"
    TOKEN_FLOWS_DEVICE_CODE_SCOPES_INVALID = 'token.flows.device-code.scopes.invalid',
    TOKEN_FLOWS_DEVICE_CODE_CLIENT_INVALID = 'token.flows.device-code.client.invalid',
    TOKEN_FLOWS_DEVICE_CODE_SAVE_ERROR = 'token.flows.device-code.save.error',
    // Token flow "password"
    TOKEN_FLOWS_PASSWORD_SCOPES_INVALID = 'token.flows.password.scopes.invalid',
    TOKEN_FLOWS_PASSWORD_CLIENT_INVALID = 'token.flows.password.client.invalid',
    TOKEN_FLOWS_PASSWORD_USER_INVALID = 'token.flows.password.user.invalid',
    TOKEN_FLOWS_PASSWORD_SAVE_ERROR = 'token.flows.password.save.error',
    // Token flow "refresh_token"
    TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_JWT_INVALID = 'token.flows.token.token.jwt-invalid',
    TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_NOT_REFRESH_TOKEN = 'token.flows.token.not-refresh-token',
    TOKEN_FLOWS_REFRESH_TOKEN_SCOPES_INVALID = 'token.flows.token.scopes.invalid',
    TOKEN_FLOWS_REFRESH_TOKEN_CLIENT_INVALID = 'token.flows.token.client.invalid',
    TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_DB_INVALID = 'token.flows.token.token.db-invalid',
    TOKEN_FLOWS_REFRESH_TOKEN_SAVE_ERROR = 'token.flows.token.save.error',


    // Device
    DEVICE_GRANT_TYPE_UNSUPPORTED = 'device.grant-type.unsupported',
    // Device flow "token"
    DEVICE_FLOWS_TOKEN_SLOW_DOWN = 'device.flows.token.slow-down',
    DEVICE_FLOWS_TOKEN_DEVICE_CODE_INVALID = 'device.flows.token.device-code.invalid',
    DEVICE_FLOWS_TOKEN_EXPIRED = 'device.flows.token.expired',
    DEVICE_FLOWS_TOKEN_PENDING = 'device.flows.token.pending',
    DEVICE_FLOWS_TOKEN_ACCESS_DENIED = 'device.flows.token.access-denied',
    DEVICE_FLOWS_TOKEN_SAVE_ERROR = 'device.flows.token.save.error',


    // Authentication
    AUTHENTICATION_TOKEN_MISSING = 'authentication.token.missing',
    AUTHENTICATION_TOKEN_JWT_EXPIRED = 'authentication.token.jwt.expired',
    AUTHENTICATION_TOKEN_DB_EXPIRED = 'authentication.token.db.expired',
    AUTHENTICATION_TOKEN_NOT_ACCESS_TOKEN = 'authentication.token.not-access-token',
    AUTHENTICATION_SCOPES_INVALID = 'authentication.scopes.invalid',
}