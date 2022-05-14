export type ExpressMiddleware = (req: any, res: any, next: any) => void;

export type ARTokensResponse = {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token?: string;
    refresh_token_expires_in?: number;
};

export type ErrorRequest = 'invalid_request' | 'invalid_client' | 'invalid_grant' | 'invalid_scope' | 'unauthorized_client' | 'unsupported_grant_type';

export type RedirectErrorRequest = 'invalid_request' | 'access_denied' | 'unauthorized_client' | 'unsupported_response_type' | 'invalid_scope' | 'server_error' | 'temporarily_unavailable';