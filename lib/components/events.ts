export enum Events {
    // Authorization
    AUTHORIZATION_REDIRECT_URI_INVALID = 'authorization.redirect-uri.invalid',
    AUTHORIZATION_SCOPES_INVALID = 'authorization.scopes.invalid',
    AUTHORIZATION_USERGAENT_INVALID = 'authorization.user-agent.invalid',
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
    TOKEN_FLOWS_DEVICE_CODE_SLOW_DOWN = 'token.flows.device-code.slow-down',
    TOKEN_FLOWS_DEVICE_CODE_DEVICE_CODE_INVALID = 'token.flows.device-code.device-code.invalid',
    TOKEN_FLOWS_DEVICE_CODE_EXPIRED = 'token.flows.device-code.expired',
    TOKEN_FLOWS_DEVICE_CODE_PENDING = 'token.flows.device-code.pending',
    TOKEN_FLOWS_DEVICE_CODE_ACCESS_DENIED = 'token.flows.device-code.access-denied',
    TOKEN_FLOWS_DEVICE_CODE_SAVE_ERROR = 'token.flows.device-code.save.error',
    // Token flow "password"
    TOKEN_FLOWS_PASSWORD_SCOPES_INVALID = 'token.flows.password.scopes.invalid',
    TOKEN_FLOWS_PASSWORD_CLIENT_INVALID = 'token.flows.password.client.invalid',
    TOKEN_FLOWS_PASSWORD_USER_INVALID = 'token.flows.password.user.invalid',
    TOKEN_FLOWS_PASSWORD_SAVE_ERROR = 'token.flows.password.save.error',
    // Token flow "refresh_token"
    TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_JWT_INVALID = 'token.flows.refresh-token.token.jwt-invalid',
    TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_NOT_REFRESH_TOKEN = 'token.flows.refresh-token.not-refresh-token',
    TOKEN_FLOWS_REFRESH_TOKEN_SCOPES_INVALID = 'token.flows.refresh-token.scopes.invalid',
    TOKEN_FLOWS_REFRESH_TOKEN_CLIENT_INVALID = 'token.flows.refresh-token.client.invalid',
    TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_DB_INVALID = 'token.flows.refresh-token.token.db-invalid',
    TOKEN_FLOWS_REFRESH_TOKEN_SAVE_ERROR = 'token.flows.refresh-token.save.error',


    // Device
    DEVICE_GRANT_TYPE_UNSUPPORTED = 'device.grant-type.unsupported',
    DEVICE_SCOPES_INVALID = 'device.scopes.invalid',
    // Device flow "token"
    DEVICE_FLOWS_TOKEN_CLIENT_INVALID = 'token.flows.device-code.client.invalid',
    DEVICE_FLOWS_TOKEN_SAVE_ERROR = 'token.flows.device-code.save.error',


    // Authentication
    AUTHENTICATION_TOKEN_MISSING = 'authentication.token.missing',
    AUTHENTICATION_TOKEN_JWT_EXPIRED = 'authentication.token.jwt.expired',
    AUTHENTICATION_TOKEN_DB_EXPIRED = 'authentication.token.db.expired',
    AUTHENTICATION_TOKEN_NOT_ACCESS_TOKEN = 'authentication.token.not-access-token',
    AUTHENTICATION_SCOPES_INVALID = 'authentication.scopes.invalid',
}