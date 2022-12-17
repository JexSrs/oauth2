export type ExpressMiddleware = (req: any, res: any, next: any) => any;

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
    clientId: any;
    user?: any;
    scopes: string[];
};

export type THAuthorizationCodeSave = {
    authorizationCode: string;
    expiresAt: number;
    clientId: any;
    user: any;
    codeChallenge?: string;
    codeChallengeMethod?: string;
};

export type THAuthorizationCodeAsk = {
    authorizationCode: string;
    clientId: any;
    user: any;
};

export type THAccessTokenAsk = {
    accessToken: string;
    clientId: any;
    user: any;
};

export type THRefreshTokenAsk = {
    refreshToken: string;
    clientId: any;
    user: any;
};

export type DFCodeSave = {
    clientId: any;
    deviceCode: string;
    userCode: string;
    interval: number;
    expiresAt: number;
    scopes: string[];
    status: 'pending' | 'completed'
};

export type DFCodeAsk = {
    clientId: any;
    deviceCode: string;
};

export type RevocationAsk = {
    clientId: any;
    user?: any;
} & ({
    what: 'access_token'
    accessToken: string;
} | {
    what: 'refresh_token' | 'record';
    refreshToken: string;
});

export type PlusUN<T> = T | null | undefined;
