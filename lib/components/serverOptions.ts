export type DBTokenSave = {
    accessToken: string;
    accessTokenExpiresAt: number;
    payload: object;
    refreshToken?: string;
    refreshTokenExpiresAt?: number;
};

type DBAccessTokenLoad = {
    accessToken: string;
    accessTokenExpiresAt: number;
    payload: object;
};

type DBRefreshTokenLoad = {
    refreshToken: string;
    refreshTokenExpiresAt: number;
};

type DBTokenRemove = {
    accessToken: string;
    accessTokenExpiresAt: number;
    payload: object;
};

export type DBAuthorizationCodeSave = {
    authorizationCode: string;
    expiresAt: number;
    clientId: string;
    scopes: string[];
    user: any;
    redirect_uri: string;
};

type DBAuthorizationCodeAsk = {
    authorizationCode: string;
    expiresAt: number;
    clientId: string;
};


export type DatabaseFunctions = {
    /**
     * The function that will save the access and refresh tokens to the database.
     * @param data
     * @return boolean True on succeed, false otherwise.
     */
    saveToken: (data: DBTokenSave) => Promise<boolean>;
    /**
     * The function that will load the accessToken from database.
     * @param data
     * @return {string|null} The access token if it exists or null otherwise.
     */
    loadAccessToken: (data: DBAccessTokenLoad) => Promise<string | null>;
    /**
     * The function that will load th refreshToken from database.
     * @param data
     * @return {string|null} The refresh token if it exists or null otherwise.
     */
    loadRefreshToken: (data: DBRefreshTokenLoad) => Promise<string | null>;
    /**
     * The function that will remove the access & refresh tokens from the database.
     * @param data
     * @return boolean True on succeed, false otherwise.
     */
    removeToken: (data: DBTokenRemove) => Promise<boolean>;
    /**
     * The function that will save the authorization code to the database.
     * @param data
     * @return boolean True on succeed, false otherwise.
     */
    saveAuthorizationCode: (data: DBAuthorizationCodeSave) => Promise<boolean>;
    /**
     * The function that will load the authorization code from database.
     * @param data
     * @return {string|null} The authorization code if it exists or null otherwise.
     */
    loadAuthorizationCode: (data: DBAuthorizationCodeAsk) => Promise<DBAuthorizationCodeSave | null>;
    /**
     * The function that will remove the authorization code from the database.
     * @param data
     * @return boolean True on succeed, false otherwise.
     */
    removeAuthorizationCode: (data: DBAuthorizationCodeAsk) => Promise<boolean>;
};

export type ServerOptions = {
    /**
     * Enabled grant types.
     * Defaults to ['authorization-code', 'resource-owner-credentials', 'refresh-token'].
     */
    allowedGrantTypes?: ('authorization-code' | 'implicit' | 'resource-owner-credentials' | 'client-credentials' | 'refresh-token')[];
    /**
     * Override token location.
     * Defaults to req.headers['authorization'].
     * @param req The request instance.
     * @return string The token that the client passed.
     */
    getToken?: (req: any) => string;
    /**
     * The token secret that will be used to sign the tokens.
     * This will be used only if default implementation is used for token sign/verification.
     */
    secret: string;
    /**
     * The access token's lifetime in seconds.
     * If set to null, then the token will never expire.
     * Defaults to 86400 seconds (1 day).
     */
    accessTokenLifetime?: number | null;
    /**
     * Whether a refresh token will be generated alongside the access token.
     * Defaults to true.
     */
    allowRefreshToken?: boolean;
    /**
     * The refresh token's lifetime in seconds.
     * If set to null, then the token will never expire.
     * Defaults to 864000 seconds (10 days).
     */
    refreshTokenLifetime?: number | null;
    /**
     * The authorization code's lifetime in seconds.
     * Defaults to 300 seconds (5 minutes).
     */
    authorizationCodeLifetime?: number;
    /**
     * Override payload location (when the verification is complete where to save the verified payload,
     * so it can be accessed later by the app).
     * Defaults to req.oauth2.
     * @param req The request instance.
     * @param payload The payload that will be saved at the request instance.
     */
    payloadLocation?: (req: any, payload: object) => void;
    /**
     * Get authenticated user identification (most likely and id).
     * This will be included in payloads so do not add sensitive data.
     * @param req The request instance.
     * @return The user's identification.
     */
    getUser: (req: any) => string | string[] | object | object[] | number | number[];
    /**
     * Override the database's functions needed for storing and accessing the tokens.
     * Defaults to memory.
     */
    database?: DatabaseFunctions;
    /**
     * Set an array of valid scopes, if the client sends one or more scopes that are not
     * listed here, it will respond with the appropriate error message.
     * Defaults to ['read', 'write'].
     */
    acceptedScopes?: string[] | ((scope: string) => Promise<boolean>);
    /**
     * The delimiter that will be used to split the scope string.
     * Defaults tp ' ' (one space character).
     */
    scopeDelimiter?: string;
    /**
     * Specify the minimum state length that the client will send during authorization.
     * Defaults to 8 characters.
     */
    minStateLength?: number;
    /** Validate that the redirect uri matches the client.
     * @param client_id
     * @param redirect_uri
     * @return True if validation passes, false otherwise.
     */
    validateRedirectUri: (client_id: string, redirect_uri: string) => Promise<boolean>;
    /**
     * Validates that the client in question is registered.
     * @param client_id The client's id.
     * @param client_secret The client's secret.
     * @return boolean True if validation succeeds, false otherwise.
     */
    validateClient: (client_id: string, client_secret: string) => Promise<boolean>;
};