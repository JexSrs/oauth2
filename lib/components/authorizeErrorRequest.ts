export enum AuthorizeErrorRequest {
    INVALID_REQUEST = 'invalid_request',
    ACCESS_DENIED = 'access_denied',
    UNAUTHORIZED_CLIENT = 'unauthorized_client', // TODO - use with server TODO1
    UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type',
    INVALID_SCOPE = 'invalid_scope',
    SERVER_ERROR = 'server_error',
    TEMPORARY_UNAVAILABLE = 'temporarily_unavailable',
}
