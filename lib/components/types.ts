export type ExpressMiddleware = (req: any, res: any, next: any) => void;

export type ARTokensResponse = {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token?: string;
    refresh_token_expires_in?: number;
};

export type ClientCredentials = {
    client_id: string;
    client_secret: string;
}

export type GrantType = 'authorization-code' | 'implicit' | 'resource-owner-credentials' | 'client-credentials' | 'refresh-token';