export type ExpressMiddleware = (req: any, res: any, next: any) => void;

export type ARTokens = {
    access_token: string;
    token_type: string;
    expires_in?: number;
    refresh_token?: string;
    scope: string;
};

export type OAuth2Error = {
    error: string;
    error_description?: string;
    error_uri?: string;
}

export type THTokenSave = {
    accessToken: string;
    accessTokenExpiresAt?: number;
    refreshToken?: string;
    refreshTokenExpiresAt?: number;
    clientId: string;
    user?: any;
    scopes: string[];
};

export type THAuthorizationCodeSave = {
    authorizationCode: string;
    expiresAt: number;
    clientId: string;
    scopes: string[];
    user: any;
    redirectUri: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
};

export type THAuthorizationCodeAsk = {
    authorizationCode: string;
    clientId: string;
    user: string;
};

export type THAccessTokenAsk = {
    accessToken: string;
    clientId: string;
    user: any;
};

export type THRefreshTokenAsk = {
    refreshToken: string;
    clientId: string;
    user: string;
};

export type DFCodeSave = {
    clientId: string;
    deviceCode: string;
    userCode: string;
    interval: number;
    expiresAt: number;
    scopes: string[];
    status: 'pending' | 'completed'
};

export type DFCodeAsk = {
    clientId: string;
    deviceCode: string;
};