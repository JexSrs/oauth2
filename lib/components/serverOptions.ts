type DBTokenSave = {
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

type DBAuthorizationCodeSave = {
    authorizationCode: string;
    expiresAt: number;
    payload: object;
};

type DBAuthorizationCodeLoad = {
    authorizationCode: string;
    expiresAt: number;
    payload: object;
};

type DBAuthorizationCodeRemove = {
    authorizationCode: string;
    expiresAt: number;
    payload: object;
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
    loadAuthorizationCode: (data: DBAuthorizationCodeLoad) => Promise<string | null>;
    /**
     * The function that will remove the authorization code from the database.
     * @param data
     * @return boolean True on succeed, false otherwise.
     */
    removeAuthorizationCode: (data: DBAuthorizationCodeRemove) => Promise<boolean>;
};

export type ServerOptions = {
    /**
     * Override token location.
     * Defaults to req.headers['authorization'].
     * @param req The request instance.
     * @return string The token that the client passed.
     */
    getToken: (req: any) => string;
    /**
     * The token secret that will be used to sign the tokens.
     * This will be used only if default implementation is used for token sign/verification.
     * Defaults to random 64 characters.
     * CAUTION! It is recommended to pass your own secret to avoid verification in case your app restarts.
     */
    secret: string;
    /**
     * Override the token sign and verification process.
     * It will be used to create and validate tokens such as: access token, refresh token, authorization code.
     * Defaults to JSONWebToken implementation.
     */
    tokenUtils: {
        /**
         * Override token generation.
         * @param payload The payload that needs to be saved inside the token.
         * @param expiresIn The expiration time in seconds after the token was generated. If undefined then no expiration was provided.
         * @return string The generated token.
         */
        sign: (payload: object, expiresIn?: number) => string;
        /**
         * Override token verification.
         * @param token The token supplied from the client.
         * @return {object | null} The payload if the verification was succeeded or null otherwise.
         */
        verify: (token: string) => object | null;
    };
    /**
     * The access token's lifetime in seconds.
     * If set to null, then the token will never expire.
     * Defaults to 86400 seconds (1 day).
     */
    accessTokenLifetime: number | null;
    /**
     * Whether a refresh token will be generated alongside the access token.
     * Defaults to true.
     */
    allowRefreshToken: boolean;
    /**
     * The refresh token's lifetime in seconds.
     * If set to null, then the token will never expire.
     * Defaults to 864000 seconds (10 days).
     */
    refreshTokenLifetime: number | null;
    /**
     * The authorization code's lifetime in seconds.
     * Defaults to 300 seconds (5 minutes).
     */
    authorizationCodeLifetime: number;
    /**
     * Override payload location (when the verification is complete where to save the verified payload,
     * so it can be accessed later by the app).
     * Defaults to req.oauth2.
     * @param req The request instance.
     * @param payload The payload that will be saved at the request instance.
     */
    payloadLocation: (req: any, payload: object) => void;
    /**
     * Set the data that will be included at the payload.
     * The payload will already contain the client_id that was provided during the authorization.
     * Defaults to {}.
     * @param req The request instance.
     */
    includeToPayload: (req: any) => object;
    /**
     * Override the database's functions needed for storing and accessing the tokens.
     * Defaults to memory.
     */
    database: DatabaseFunctions;
    /**
     * Set an array of valid scopes, if the client sends one or more scopes that are not
     * listed here, it will respond with the appropriate error message.
     * Defaults to ['read', 'write'].
     */
    acceptedScopes: string[] | ((scope: string) => Promise<boolean>);
    /**
     * The delimiter that will be used to split the scope string.
     * Defaults tp ' ' (one space character).
     */
    scopeDelimiter: string;
    /**
     * Specify the minimum state length that the client will send during authorization.
     * Defaults to 8 characters.
     */
    minStateLength: number;
    /**
     * Validates that the client in question is registered.
     * Defaults to true.
     * CAUTION! It is highly recommended to pass your own validation function, so you will not allow
     * just anyone to generate tokens for themselves.
     * @param client_id The client's id.
     * @param client_secret The client's secret. If null then there is no need to authenticate client.
     * @param redirect_uri The redirect_uri passed by the client. This will be included in the registered check.
     * @return boolean True if validation succeeds, false otherwise.
     */
    validateClient: (client_id: string, client_secret: string | null, redirect_uri: string) => Promise<boolean>;
};