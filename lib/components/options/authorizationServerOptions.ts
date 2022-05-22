import {GrantTypes} from "../GrantTypes";

export type THTokenSave = {
    accessToken: string;
    accessTokenExpiresAt: number;
    refreshToken?: string;
    refreshTokenExpiresAt?: number;
    clientId: string;
    user: any;
    scopes: string[];
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
    codeChallenge?: string;
    codeChallengeMethod?: string;
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
     * @return {boolean} True on succeed, false otherwise.
     */
    saveTokens: (data: THTokenSave) => Promise<boolean>;
    /**
     * The function that will load the accessToken from database.
     * @param data
     * @return {string|null} The access token if it exists.
     */
    getAccessToken: (data: THAccessTokenAsk) => Promise<string | null | undefined> | string | null | undefined;
    /**
     * The function that will load th refreshToken from database.
     * @param data
     * @return {string|null} The refresh token if it exists.
     */
    getRefreshToken: (data: THRefreshTokenAsk) => Promise<string | null | undefined> | string | null | undefined;
    /**
     * The function that will remove the access & refresh tokens from the database.
     * @param data
     * @return {boolean} true on succeed, false otherwise.
     */
    deleteTokens: (data: THRefreshTokenAsk) => Promise<boolean>;
    /**
     * The function that will save the authorization code to the database.
     * @param data
     * @return {boolean} true on succeed, false otherwise.
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
     * @return {boolean} true on succeed, false otherwise.
     */
    deleteAuthorizationCode: (data: THAuthorizationCodeAsk) => Promise<boolean>;
};

export type AuthorizationServerOptions = {
    /**
     * Which grant types will be available for the app.
     * If GrantTypes.REFRESH_TOKEN is included then a refresh token will be generated with the access tokens.
     * Defaults to [GrantTypes.AUTHORIZATION_CODE, GrantTypes.REFRESH_TOKEN].
     */
    grantTypes: GrantTypes[];
    /**
     * Override token location during authentication.
     * Defaults to req.headers['authorization'].
     * @param req The request instance.
     * @return {string} The token that the client passed.
     */
    getToken: (req: any) => string;
    /**
     * Override payload location (when the verification is complete where to save the verified payload,
     * so it can be accessed later by the app). The payload will be an object that contains {client_id, user, scopes}.
     * Defaults to req.payload.
     * @param req The request instance.
     * @param payload The payload that will be saved at the request instance.
     */
    setPayloadLocation: (req: any, payload: object) => void;
    /**
     * Whether to use PKCE during authorization code flow.
     * Defaults tp true.
     */
    usePKCE: boolean;
    /**
     * If you are using PKCE, whether code challenge method plain is allowed
     * or S256 is mandatory.
     * Defaults to false.
     */
    allowCodeChallengeMethodPlain: boolean;
    /**
     * Override client credentials location.
     * If one of the credentials is not found return undefined, null empty or string.
     * Default to authorization header: Basic <BASE64({CLIENT ID}:{CLIENT SECRET})>
     * @param req
     * @return {object} the client_id and client_secret.
     */
    getClientCredentials: (req: any) => { client_id?: string | null; client_secret?: string | null; };
    /**
     * The token secret that will be used to sign the tokens using JSONWebToken (JWT).
     */
    secret: string;
    /**
     * The access token's lifetime in seconds.
     * If set to null, then the token will never expire and no refresh token will be generated.
     * Defaults to 86400 seconds (1 day).
     */
    accessTokenLifetime: number | null;
    /**
     * The refresh token's lifetime in seconds.
     * If set to null, then the token will never expire until a refresh happen
     * or is manually removed from the database.
     * Defaults to 864000 seconds (10 days).
     */
    refreshTokenLifetime: number | null;
    /**
     * The authorization code's lifetime in seconds.
     * Defaults to 60 seconds (1 minute).
     */
    authorizationCodeLifetime: number;
    /**
     * Override the database's functions needed for storing and accessing the tokens.
     * Defaults to memory.
     */
    tokenHandler: Partial<TokenHandlerFunctions>;
    /**
     * Get an identification of the user that was authenticated in this request.
     * This will be included in payloads so do not add sensitive data.
     * @param req The request instance.
     * @return {any} The user's identification.
     */
    getUser: (req: any) => string | object | number | (string | object | number | boolean)[] | null;
    /**
     * The delimiter that will be used to split the scope string.
     * Defaults to ' ' (one space character).
     */
    scopeDelimiter: string;
    /**
     * A function that asks if the passed scopes are valid. Not if permitted, this will be handled by the user.
     * If no scopes where send with the request then this function will be called once with an empty array.
     * @param scopes
     * @return {boolean} true if scope is valid, false otherwise
     */
    isScopesValid: (scopes: string[]) => (Promise<boolean> | boolean);
    /**
     * Validate that the redirect uri that was passed during authorization is
     * registered matches the client's redirect uris.
     * @param client_id
     * @param redirect_uri
     * @return {boolean} true if validation passes, false otherwise.
     */
    validateRedirectURI: (client_id: string, redirect_uri: string) => Promise<boolean>;
    /**
     * Validates that the client in question is registered.
     * @param client_id The client's id.
     * @param client_secret The client's secret.
     * @return {boolean} true if validation succeeds, false otherwise.
     */
    validateClient: (client_id?: string | null, client_secret?: string | null) => Promise<boolean>;
    /**
     * Validates user's credentials.
     * This will be used in the Resource Owner Credentials flow and nowhere else.
     * Do not include sensitive data because the result will be stored to the payload.
     * @param username
     * @param password
     * @return {object|null} The user's identification or null if validation failed.
     */
    validateUser: (username?: string | null, password?: string | null) => Promise<object | null>;
    /**
     * If this function return true, it will abort the authorization requests
     * with the justification of temporary unavailable.
     * Can also be an asynchronous function in case you want to ask a remote service.
     * Defaults to false.
     * @return {boolean} true to abort, false otherwise.
     */
    isTemporaryUnavailable: boolean | ((req: any) => Promise<boolean>);
    /**
     * The issuer parameter while signing the tokens.
     * Defaults to empty string.
     */
    issuer: string;
    /**
     * If the request was made using an embedded web view the request will be rejected.
     * The agent header will be used to verify the browser that makes the request.
     * Defaults to true.
     */
    rejectEmbeddedWebViews: boolean;
};