import {AuthorizationServerOptions} from "./components/options/authorizationServerOptions";
import {ExpressMiddleware} from "./components/types";
import {
    authenticateError,
    buildRedirectURI,
    checkOptions,
    codeChallengeHash,
    tokenError,
    authorizeError,
    getGrantType, isEmbeddedWebView,
    mergeOptions,
    parseScopes
} from "./modules/utils";
import {generateARTokens, signToken, verifyToken} from './modules/tokenUtils'
import {memory} from "./modules/memory";
import {GrantType} from "./components/GrantType";
import {TokenErrorRequest} from "./components/errors/tokenErrorRequest";
import {AuthorizeErrorRequest} from "./components/errors/authorizeErrorRequest";
import {AuthenticateErrorRequest} from "./components/errors/authenticateErrorRequest";

export class AuthorizationServer {

    // TODO - add event listeners, maybe using .on(event, listener);
    //      - Add listener for invalid refreshToken to check if token is stolen etc (for clients without a secret)
    //      - Add listener if authorization code is used twice (it should be treated as an attack and if possible revoke tokens)
    //      - https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/

    // TODO - add new implementation, maybe using .use('implementation', function)
    //      - Maybe add like google device: https://www.oauth.com/oauth2-servers/device-flow/
    //      - Abort grantTypes array and use .use('implementation', options) to include flows

    // TODO - Add a way to identify if scopes are valid with client_id & user_id (maybe pass req, that contains query and user)
    //      - This also can be checked before authorization at previous middleware by parsing and checking scopes

    // TODO - https://stackoverflow.com/questions/5925954/what-are-bearer-tokens-and-token-type-in-oauth-2

    // TODO - Add a custom function that will do extra checks the user wants.

    // TODO - Add checks for scopes when authorizing client (client may not be allowed to access specific scopes)

    // TODO - Add option to do all checks asynchronous with Promise.all([w1, w2, w3]).spread(function (r1, r2, r3) {})

    private readonly options: Partial<AuthorizationServerOptions>;

    constructor(options: Partial<AuthorizationServerOptions>) {
        let opts: Partial<AuthorizationServerOptions> = options;

        if (!opts.grantTypes)
            opts.grantTypes = [GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN];

        // Remove duplicate records
        opts.grantTypes = opts.grantTypes.filter((e, i) => opts.grantTypes.indexOf(e) === i);

        if (!opts.getToken)
            opts.getToken = (req) => req.headers['authorization']?.split(' ')?.[1];

        if (!opts.setPayloadLocation)
            opts.setPayloadLocation = (req, payload) => req.payload = payload;

        if (typeof opts.usePKCE === 'undefined') opts.usePKCE = true;

        if (typeof opts.allowCodeChallengeMethodPlain === 'undefined')
            opts.allowCodeChallengeMethodPlain = false;

        if (!opts.getClientCredentials) opts.getClientCredentials = (req: any) => {
            let authHeader = req.headers['authorization'];
            let decoded = authHeader && Buffer.from(authHeader, 'base64').toString() || '';

            let [client_id, client_secret] = /^([^:]*):(.*)$/.exec(decoded);
            return {client_id, client_secret};
        };

        if (typeof opts.accessTokenLifetime !== 'undefined') {
            if (opts.accessTokenLifetime <= 0 || Math.trunc(opts.accessTokenLifetime) !== opts.accessTokenLifetime)
                throw new Error('accessTokenLifetime is not positive integer.')
        } else opts.accessTokenLifetime = 86400;

        if (typeof opts.refreshTokenLifetime === 'undefined')
            opts.refreshTokenLifetime = 864000;
        else if (opts.refreshTokenLifetime <= 0 || Math.trunc(opts.refreshTokenLifetime) !== opts.refreshTokenLifetime)
            throw new Error('refreshTokenLifetime is not positive integer.')

        if (typeof opts.authorizationCodeLifetime === 'undefined')
            opts.authorizationCodeLifetime = 60;
        else if (opts.authorizationCodeLifetime <= 0 || Math.trunc(opts.authorizationCodeLifetime) !== opts.authorizationCodeLifetime)
            throw new Error('authorizationCodeLifetime is not positive integer.')

        if (!opts.tokenHandler)
            opts.tokenHandler = memory();

        if (!opts.scopeDelimiter)
            opts.scopeDelimiter = ' ';

        if(typeof opts.isTemporaryUnavailable === 'undefined')
            opts.isTemporaryUnavailable = false;

        if(!opts.issuer)
            opts.issuer = '';

        if(typeof opts.rejectEmbeddedWebViews === 'undefined')
            opts.rejectEmbeddedWebViews = true;

        if(typeof opts.isGrantTypeAllowed === 'undefined')
            opts.isGrantTypeAllowed = (client_id) => true;

        this.options = opts;
    }

    private static async authorizationCode1(req: any, res: any, opts: Partial<AuthorizationServerOptions>, scopes: string[], user: any): Promise<void> {
        let {state, client_id, redirect_uri, code_challenge, code_challenge_method} = req.query;

        // Check for PKCE
        if (opts.usePKCE) {
            if (!code_challenge)
                return authorizeError(res, AuthorizeErrorRequest.INVALID_REQUEST, redirect_uri, state, 'Missing code challenge.')
            if (!['S256', 'plain'].includes(code_challenge_method) || (code_challenge_method === 'plain' && !opts.allowCodeChallengeMethodPlain))
                return authorizeError(res, AuthorizeErrorRequest.INVALID_REQUEST, redirect_uri, state, 'Code challenge method is not valid.')
        }

        // Generate authorization code
        let payload = {client_id, user};
        let code = signToken(payload, opts.secret, opts.issuer, opts.authorizationCodeLifetime);

        // Save authorization code to database
        let dbRes = await opts.tokenHandler.saveAuthorizationCode({
            authorizationCode: code,
            expiresAt: Math.trunc((Date.now() + opts.authorizationCodeLifetime * 1000) / 1000),
            clientId: client_id,
            redirectUri: redirect_uri,
            user,
            scopes,
            codeChallenge: code_challenge,
            codeChallengeMethod: code_challenge_method
        });
        if(!dbRes) {
            authorizeError(res, AuthorizeErrorRequest.SERVER_ERROR, redirect_uri, state, 'Encountered an unexpected database error')
            return;
        }

        // Respond with authorization code
        res.header('Cache-Control', 'no-store').redirect(buildRedirectURI(redirect_uri, {code, state}));
    }

    private static async implicit(req: any, res: any, opts: Partial<AuthorizationServerOptions>, scopes: string[], user: any): Promise<void> {
        let {state, client_id, redirect_uri} = req.query;

        // Generate access & refresh tokens
        let payload = {client_id, user, scopes};
        let tokens = await generateARTokens(payload, req, opts, false);

        // Respond with tokens
        res.header('Cache-Control', 'no-store').redirect(buildRedirectURI(redirect_uri, {...tokens, state}));
    }

    private static async authorizationCode2(req: any, res: any, opts: Partial<AuthorizationServerOptions>): Promise<void> {
        let {client_id, client_secret} = opts.getClientCredentials(req);
        let {code, redirect_uri, code_verifier} = req.body;
        if (!client_id) client_id = req.body.client_id;

        // Check PKCE parameter
        if (opts.usePKCE && !code_verifier)
            return tokenError(res, TokenErrorRequest.INVALID_REQUEST, 'Missing code verifier')

        // Token verification
        let authCodePayload: any = verifyToken(code, opts.secret, opts.issuer);
        if (!authCodePayload)
            return tokenError(res, TokenErrorRequest.INVALID_GRANT, 'Authorization code is not valid or has expired');

        // Payload verification
        if (authCodePayload.client_id !== client_id)
            return tokenError(res, TokenErrorRequest.INVALID_GRANT, 'Authorization code does not belong to the client');

        // Do database request at last to lessen db costs.
        if (!(await opts.validateClient(client_id, client_secret)))
            return tokenError(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        // Database verification
        let dbCode = await opts.tokenHandler.getAuthorizationCode({
            clientId: client_id,
            authorizationCode: code,
            user: authCodePayload.user
        });

        if (!dbCode || dbCode.authorizationCode !== code)
            return tokenError(res, TokenErrorRequest.INVALID_GRANT, 'Authorization code is not valid or has expired');

        if (redirect_uri !== dbCode.redirectUri)
            return tokenError(res, TokenErrorRequest.INVALID_GRANT, 'Redirect URI is not the same that was used during authorization code grant');

        // Check PKCE
        if (opts.usePKCE) {
            if (dbCode.codeChallenge !== codeChallengeHash((dbCode.codeChallengeMethod as any), code_verifier))
                return tokenError(res, TokenErrorRequest.INVALID_GRANT, 'Code verifier is not valid');
        }

        // Database delete
        await opts.tokenHandler.deleteAuthorizationCode({
            clientId: client_id,
            authorizationCode: code,
            user: authCodePayload.user
        });

        // Generate access & refresh tokens
        let response = await generateARTokens({
            client_id,
            user: authCodePayload.user,
            scopes: authCodePayload.scopes
        }, req, opts);
        res.status(200).header('Cache-Control', 'no-store').json(response);
    }

    private static async resourceOwnerCredentials(req: any, res: any, opts: Partial<AuthorizationServerOptions>, scopes: string[]): Promise<void> {
        let {client_id, client_secret} = opts.getClientCredentials(req);
        let {username, password} = req.body;

        // Do database request at last to lessen db costs.
        if (!(await opts.validateClient(client_id, client_secret)))
            return tokenError(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        let user = await opts.validateUser(username, password);
        if (!user) return tokenError(res, TokenErrorRequest.INVALID_GRANT, 'Client authentication failed');

        let payload = {client_id, user, scopes};
        // Generate access & refresh tokens
        let response = await generateARTokens(payload, req, opts);
        res.status(200).header('Cache-Control', 'no-store').json(response);
    }

    private static async clientCredentials(req: any, res: any, opts: Partial<AuthorizationServerOptions>, scopes: string[]): Promise<void> {
        let {client_id, client_secret} = opts.getClientCredentials(req);

        // Do database request at last to lessen db costs.
        if (!(await opts.validateClient(client_id, client_secret)))
            return tokenError(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        // Generate access & refresh tokens
        let response = await generateARTokens({client_id, scopes}, req, opts, false);
        res.status(200).header('Cache-Control', 'no-store').json(response);
    }

    private static async refreshToken(req: any, res: any, opts: Partial<AuthorizationServerOptions>): Promise<void> {
        let {client_id, client_secret} = opts.getClientCredentials(req);
        let {scope, refresh_token} = req.body;
        if (!client_id) client_id = req.body.client_id;

        let refreshTokenPayload: any = verifyToken(refresh_token, opts.secret, opts.issuer);
        if (!refreshTokenPayload)
            return tokenError(res, TokenErrorRequest.INVALID_GRANT, 'Refresh token is not valid');

        // Check scopes - No need to check with app because the new scopes must
        // be subset of the refreshTokenPayload.scopes
        let scopes: string[] | null = scope.split(opts.scopeDelimiter);
        if (refreshTokenPayload.scopes.some(v => !scopes.includes(v)))
            return tokenError(res, TokenErrorRequest.INVALID_SCOPE, 'One or more scopes are not acceptable');

        if (refreshTokenPayload.client_id !== client_id)
            return tokenError(res, TokenErrorRequest.INVALID_GRANT, 'Refresh token does not belong to client');

        // If client_secret was passed then verify client (else it will be verified by the access token).
        if (client_secret && !(await opts.validateClient(client_id, client_secret)))
            return tokenError(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        let dbToken = await opts.tokenHandler.getRefreshToken({
            refreshToken: refresh_token,
            clientId: client_id,
            user: refreshTokenPayload.user,
        });

        if (!dbToken || dbToken !== refresh_token)
            return tokenError(res, TokenErrorRequest.INVALID_GRANT, 'Refresh token is not valid');

        // Remove old tokens from database
        await opts.tokenHandler.deleteTokens({
            refreshToken: refresh_token,
            clientId: client_id,
            user: refreshTokenPayload.user
        });

        let response = await generateARTokens({client_id, scopes}, req, opts);
        res.status(200).header('Cache-Control', 'no-store').json(response);
    }

    /**
     * Assign this function to the 'authorize' endpoint.
     */
    public authorize(options?: Partial<AuthorizationServerOptions>): ExpressMiddleware {
        const opts = mergeOptions(this.options, options);
        checkOptions(opts, 'authorize');

        return async (req, res, next) => {
            if (req.method !== 'GET') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {client_id, redirect_uri, state, scope, response_type} = req.query;

            // Validate client_id and redirect_uri
            if (!(await opts.validateRedirectURI(client_id, redirect_uri)))
                return tokenError(res, TokenErrorRequest.INVALID_REQUEST, 'Client id or redirect URI are not registered');

            if((typeof opts.isTemporaryUnavailable === 'boolean' ? opts.isTemporaryUnavailable : await opts.isTemporaryUnavailable(req)))
                return authorizeError(res, AuthorizeErrorRequest.TEMPORARY_UNAVAILABLE, redirect_uri, state, 'The authorization server is temporary unavailable.')

            if(opts.rejectEmbeddedWebViews && isEmbeddedWebView(req))
                return authorizeError(res, AuthorizeErrorRequest.INVALID_REQUEST, redirect_uri, state, 'The request was made from an embedded web view, which is not allowed.')

            let user: any;
            if ((user = opts.getUser(req)) == null)
                return authorizeError(res, AuthorizeErrorRequest.ACCESS_DENIED, redirect_uri, state, 'User did not approve request')

            let gt: GrantType | null = getGrantType(response_type);
            if (!gt || !opts.grantTypes.includes(gt))
                return authorizeError(res, AuthorizeErrorRequest.UNSUPPORTED_RESPONSE_TYPE, redirect_uri, state, 'response_type is not acceptable');

            if(!(await opts.isGrantTypeAllowed(client_id, gt)))
                return authorizeError(res, AuthorizeErrorRequest.UNAUTHORIZED_CLIENT, redirect_uri, state, 'This client is not allowed to use this grant type')

            // Validate scopes
            let scopes: string[] | null;
            if ((scopes = await parseScopes(scope, opts)) == null)
                return authorizeError(res, AuthorizeErrorRequest.INVALID_SCOPE, redirect_uri, state, 'One or more scopes are not acceptable');

            if (response_type === 'code')
                AuthorizationServer.authorizationCode1(req, res, opts, scopes, user);
            else if (response_type === 'token')
                AuthorizationServer.implicit(req, res, opts, scopes, user);
            else authorizeError(res, AuthorizeErrorRequest.INVALID_REQUEST, redirect_uri, state, 'response_type is not acceptable');

        };
    }

    /**
     * Assign this function to the 'token' endpoint.
     */
    public token(options?: Partial<AuthorizationServerOptions>): ExpressMiddleware {
        const opts = mergeOptions(this.options, options);
        checkOptions(opts, 'token');

        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {grant_type, scope} = req.body;

            let gt: GrantType | null = getGrantType(grant_type);
            if (!gt || !opts.grantTypes.includes(gt))
                return tokenError(res, TokenErrorRequest.UNSUPPORTED_GRANT_TYPE, 'grant_type is not acceptable');

            if (grant_type === 'password' || grant_type === 'client_credentials') {
                // Check scopes
                let scopes: string[] | null;
                if ((scopes = await parseScopes(scope, opts)) == null)
                    return tokenError(res, TokenErrorRequest.INVALID_SCOPE, 'One or more scopes are not acceptable');

                if (grant_type === 'password')
                    AuthorizationServer.resourceOwnerCredentials(req, res, opts, scopes);
                else if (grant_type === 'client_credentials')
                    AuthorizationServer.clientCredentials(req, res, opts, scopes);

            }
            else if (grant_type === 'authorization_code')
                AuthorizationServer.authorizationCode2(req, res, opts);
            else if (grant_type === 'refresh_token')
                AuthorizationServer.refreshToken(req, res, opts);
            else tokenError(res, TokenErrorRequest.UNSUPPORTED_GRANT_TYPE, 'grant_type is not acceptable');
        };
    }

    /**
     * This function will be used to authenticate a request if the resource and authorization server
     * are one and the same. If they are different checkout the introspection endpoint.
     * @param options
     * @param scope The scopes needed for this request. If the access token scopes are insufficient
     *              then the authentication will fail. If scope is not initialized then the scope
     *              check will be omitted.
     */
    public authenticate(options?: Partial<AuthorizationServerOptions> | string | string[], scope?: string | string[]): ExpressMiddleware {
        // Pass scopes without custom options
        if(typeof options === 'string' || Array.isArray(options)) {
            scope = options;
            options = undefined;
        }

        const opts = mergeOptions(this.options, options as any);
        checkOptions(opts, 'authenticate');

        let scopes: string[] | null = Array.isArray(scope) ? scope : scope?.split(/, */);
        return async (req, res, next) => {
            let token = opts.getToken(req);
            if (!token)
                return authenticateError(res, AuthenticateErrorRequest.INVALID_REQUEST, 'No access token was provided');

            let payload: any = verifyToken(token, opts.secret, opts.issuer);
            if (!payload)
                return authenticateError(res, AuthenticateErrorRequest.INVALID_TOKEN, 'The access token expired');

            if (scopes && payload.scopes.some(v => !scopes.includes(v)))
                return authenticateError(res, AuthenticateErrorRequest.INSUFFICIENT_SCOPE, 'Scopes re insufficient');

            let dbToken = await opts.tokenHandler.getAccessToken({
                accessToken: token,
                clientId: payload.client_id,
                user: payload.user
            });

            if (!dbToken || dbToken !== token)
                return authenticateError(res, AuthenticateErrorRequest.INVALID_TOKEN, 'The access token expired');

            opts.setPayloadLocation(req, {
                clientId: payload.client_id,
                user: payload.user,
                scopes: payload.scopes,
            });
            next();
        };
    }

    /**
     * Assign this function to the 'introspection' endpoint.
     * This endpoint is meant to be accessible only by the resource server, if you make this endpoint
     * public make sure to verify the client on your own before the request reach this function.
     * @param options
     */
    public introspection(options?: Partial<AuthorizationServerOptions>): ExpressMiddleware {
        const opts = mergeOptions(this.options, options as any);
        checkOptions(opts, 'introspection');

        const inactive = (res): void => {
            res.status(200).json({active: false});
        }

        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {token} = req.body;
            if(!token) return inactive(res);

            let payload: any = verifyToken(token, opts.secret, opts.issuer);
            if (!payload) return inactive(res);

            let dbToken = await opts.tokenHandler.getAccessToken({
                accessToken: token,
                clientId: payload.client_id,
                user: payload.user
            });

            if (!dbToken || dbToken !== token)
                return inactive(res);

            res.status(200).json({
                active: true,
                scope: payload.scopes.join(opts.scopeDelimiter),
                client_id: payload.client_id,
                user: payload.user,
                exp: payload.exp
            });
        }
    }
}