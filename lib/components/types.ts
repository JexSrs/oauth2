export type ExpressMiddleware = (req: any, res: any, next: any) => void;

export type ARTokensResponse = {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token?: string;
    scope: string;
};

export type OAuth2Error = {
    error: string;
    error_description: string;
    error_uri?: string;
}
