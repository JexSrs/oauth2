import {GrantTypes} from "./GrantTypes";

export type THTokenSave = {
    accessToken: string;
    accessTokenExpiresAt: number;
    refreshToken?: string;
    refreshTokenExpiresAt?: number;
    clientId: string;
    user: any;
};

type THAccessTokenAsk = {
    accessToken: string;
    clientId: string;
    user: any;
};

type THRefreshTokenAsk = {
    refreshToken: string;
    clientId: string;
    user: string;
};

export type THAuthorizationCodeSave = {
    authorizationCode: string;
    expiresAt: number;
    clientId: string;
    scopes: string[];
    user: any;
    redirectUri: string;
};

type THAuthorizationCodeAsk = {
    authorizationCode: string;
    clientId: string;
    user: string;
};

export type TokenHandlerFunctions = {
    /**
     * The function that will save the access and refresh tokens to the database.
     * @param data
     * @return boolean True on succeed, false otherwise.
     */
    saveTokens: (data: THTokenSave) => Promise<boolean>;
    /**
     * The function that will load the accessToken from database.
     * @param data
     * @return {string|null} The access token if it exists or null otherwise.
     */
    getAccessToken: (data: THAccessTokenAsk) => Promise<string | null>;
    /**
     * The function that will load th refreshToken from database.
     * @param data
     * @return {string|null} The refresh token if it exists or null otherwise.
     */
    getRefreshToken: (data: THRefreshTokenAsk) => Promise<string | null>;
    /**
     * The function that will remove the access & refresh tokens from the database.
     * @param data
     * @return boolean True on succeed, false otherwise.
     */
    deleteTokens: (data: THRefreshTokenAsk) => Promise<boolean>;
    /**
     * The function that will save the authorization code to the database.
     * @param data
     * @return boolean True on succeed, false otherwise.
     */
    saveAuthorizationCode: (data: THAuthorizationCodeSave) => Promise<boolean>;
    /**
     * The function that will load the authorization code from database.
     * @param data
     * @return {string|null} The authorization code if it exists or null otherwise.
     */
    getAuthorizationCode: (data: THAuthorizationCodeAsk) => Promise<THAuthorizationCodeSave | null>;
    /**
     * The function that will remove the authorization code from the database.
     * @param data
     * @return boolean True on succeed, false otherwise.
     */
    deleteAuthorizationCode: (data: THAuthorizationCodeAsk) => Promise<boolean>;
};

export type ServerOptions = {
    /**
     * Which grant types will be available for the app.
     * Defaults to [GrantTypes.AUTHORIZATION_CODE, GrantTypes.REFRESH_TOKEN].
     */
    grantTypes?: GrantTypes[];
    /**
     * Override token location during authentication.
     * Defaults to req.headers['authorization'].
     * @param req The request instance.
     * @return string The token that the client passed.
     */
    getToken?: (req: any) => string;
    /**
     * Override payload location (when the verification is complete where to save the verified payload,
     * so it can be accessed later by the app). The payload will be an object that contains {client_id, user, scopes}.
     * Defaults to req.payload.
     * @param req The request instance.
     * @param payload The payload that will be saved at the request instance.
     */
    payloadLocation?: (req: any, payload: object) => void;
    /**
     * Specify the minimum state length that the client will send during authorization.
     * Defaults to 8 characters.
     */
    minStateLength?: number;
    /**
     * Override client credentials location.
     * Default to authorization header: Basic <BASE64({CLIENT ID}:{CLIENT SECRET})>
     * @param req
     * @return the client_id and client_secret.
     */
    getClientCredentials?: (req: any) => { client_id?: string | null; client_secret?: string | null; };
    /**
     * The token secret that will be used to sign the tokens using JSONWebToken (JWT).
     */
    secret: string;
    /**
     * The access token's lifetime in seconds.
     * If set to null, then the token will never expire.
     * Defaults to 86400 seconds (1 day).
     */
    accessTokenLifetime?: number | null;
    /**
     * Whether a refresh token will be issued alongside the access token.
     * Defaults to if 'refresh-token' grant type is allowed.
     */
    issueRefreshToken?: boolean;
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
     * Override the database's functions needed for storing and accessing the tokens.
     * Defaults to memory.
     */
    tokenHandler?: TokenHandlerFunctions;
    /**
     * Get an identification of the user that was authenticated in this request.
     * This will be included in payloads so do not add sensitive data.
     * @param req The request instance.
     * @return The user's identification.
     */
    getUser: (req: any) => string | object | number | (string | object | number | boolean)[];
    /**
     * The delimiter that will be used to split the scope string.
     * Defaults to ' ' (one space character).
     */
    scopeDelimiter?: string;
    /**
     * A function that asks if a scope is valid. Not if permitted, this will be handled by the user.
     * This function will make multiple calls if more than one scopes where passed during authorization.
     * @param scope
     * @param grantType The grant type where the function was called.
     */
    isScopeValid: (scope: string, grantType: GrantTypes) => (Promise<boolean> | boolean);
    /** Validate that the redirect uri that was passed during authorization is registered matches the client's redirect uris.
     * @param client_id
     * @param redirect_uri
     * @return True if validation passes, false otherwise.
     */
    validateRedirectURI: (client_id: string, redirect_uri: string) => Promise<boolean>;
    /**
     * Validates that the client in question is registered.
     * @param client_id The client's id.
     * @param client_secret The client's secret.
     * @return True if validation succeeds, false otherwise.
     */
    validateClient: (client_id: string, client_secret: string) => Promise<boolean>;
};