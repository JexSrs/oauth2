import {ServerOptions} from "./components/serverOptions";
import {ExpressMiddleware} from "./components/types";
import {
    buildRedirectURI,
    checkOptions,
    codeChallengeHash,
    errorBody,
    errorRedirect,
    getGrantType,
    mergeOptions,
    parseScopes,
} from "./modules/utils";
import {generateARTokens, signToken, verifyToken} from './modules/tokenUtils'
import {memory} from "./modules/memory";
import {GrantTypes} from "./components/GrantTypes";
import {TokenErrorRequest} from "./components/tokenErrorRequest";
import {AuthorizeErrorRequest} from "./components/authorizeErrorRequest";


export class Server {

    // TODO - add event listeners, maybe using .on(event, listener);
    //      - Add listener for invalid refreshToken to check if token is stolen etc (for clients without a secret)
    //      - https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/
    // TODO - add event middlewares, maybe using .use(event, listener);
    // TODO - add new implementation, maybe using .use('implementation', function)
    // TODO - https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/

    // TODO - Handle database errors (try/catch & return false)

    private readonly options: Partial<ServerOptions>;

    constructor(options: Partial<ServerOptions>) {
        let opts: Partial<ServerOptions> = options;

        if (!opts.grantTypes)
            opts.grantTypes = [GrantTypes.AUTHORIZATION_CODE, GrantTypes.REFRESH_TOKEN];

        // Remove duplicate records
        opts.grantTypes = opts.grantTypes.filter((e, i) => opts.grantTypes.indexOf(e) === i);

        if (!opts.getToken)
            opts.getToken = (req) => req.headers['authorization']?.split(' ')?.[1];

        if (!opts.setPayloadLocation)
            opts.setPayloadLocation = (req, payload) => req.payload = payload;

        if (typeof opts.allowNonHTTPSRedirectURIs === 'undefined')
            opts.allowNonHTTPSRedirectURIs = false;

        if (typeof opts.usePKCE === 'undefined')
            opts.usePKCE = true;

        if (typeof opts.allowCodeChallengeMethodPlain === 'undefined')
            opts.allowCodeChallengeMethodPlain = false;

        if (!opts.minStateLength)
            opts.minStateLength = 8;

        if (!opts.getClientCredentials)
            opts.getClientCredentials = (req: any) => {
                let authHeader = req.headers['authorization'];
                let decoded = authHeader
                    && Buffer.from(authHeader, 'base64').toString()
                    || '';

                let [client_id, client_secret] = /^([^:]*):(.*)$/.exec(decoded);
                return {client_id, client_secret};
            };

        if (typeof opts.accessTokenLifetime !== 'undefined') {
            if (opts.accessTokenLifetime <= 0 || Math.trunc(opts.accessTokenLifetime) !== opts.accessTokenLifetime)
                throw new Error('accessTokenLifetime is not positive integer.')
        } else opts.accessTokenLifetime = 86400;

        if (typeof opts.issueRefreshToken === 'undefined')
            opts.issueRefreshToken = opts.grantTypes.includes(GrantTypes.REFRESH_TOKEN);

        if (typeof opts.refreshTokenLifetime === 'undefined')
            opts.refreshTokenLifetime = 864000;
        else if (opts.refreshTokenLifetime <= 0 || Math.trunc(opts.refreshTokenLifetime) !== opts.refreshTokenLifetime)
            throw new Error('refreshTokenLifetime is not positive integer.')

        if (typeof opts.authorizationCodeLifetime === 'undefined')
            opts.authorizationCodeLifetime = 864000;
        else if (opts.authorizationCodeLifetime <= 0 || Math.trunc(opts.authorizationCodeLifetime) !== opts.authorizationCodeLifetime)
            throw new Error('authorizationCodeLifetime is not positive integer.')

        if (!opts.tokenHandler)
            opts.tokenHandler = memory();

        if (!opts.scopeDelimiter)
            opts.scopeDelimiter = ' ';

        this.options = opts;
    }

    private static async authorizationCode1(req: any, res: any, opts: Partial<ServerOptions>, scopes: string[], user: any): Promise<void> {
        let {state, client_id, redirect_uri, code_challenge, code_challenge_method} = req.query;

        // Check for PKCE
        if (opts.usePKCE) {
            if (!code_challenge)
                return errorRedirect(res, AuthorizeErrorRequest.INVALID_REQUEST, redirect_uri, state, 'Missing code challenge.')
            if (!['S256', 'plain'].includes(code_challenge_method) || (code_challenge_method === 'plain' && !opts.allowCodeChallengeMethodPlain))
                return errorRedirect(res, AuthorizeErrorRequest.INVALID_REQUEST, redirect_uri, state, 'Code challenge method is not valid.')
        }

        // Generate authorization code
        let payload = {client_id, user};
        let code = signToken(payload, opts.secret, opts.authorizationCodeLifetime);

        // Save authorization code to database
        await opts.tokenHandler.saveAuthorizationCode({
            authorizationCode: code,
            expiresAt: Math.trunc((Date.now() + opts.authorizationCodeLifetime * 1000) / 1000),
            clientId: client_id,
            redirectUri: redirect_uri,
            user,
            scopes,
            codeChallenge: code_challenge,
            codeChallengeMethod: code_challenge_method
        });

        // Respond with authorization code
        res.header('Cache-Control', 'no-store').redirect(buildRedirectURI(redirect_uri, {code, state}));
    }

    private static async implicit(req: any, res: any, opts: Partial<ServerOptions>, scopes: string[], user: any): Promise<void> {
        let {state, client_id, redirect_uri} = req.query;

        // Generate access & refresh tokens
        let payload = {client_id, user, scopes};
        let tokens = await generateARTokens(payload, req, opts);

        // Respond with tokens
        res.header('Cache-Control', 'no-store').redirect(buildRedirectURI(redirect_uri, {...tokens, state}));
    }

    private static async authorizationCode2(req: any, res: any, opts: Partial<ServerOptions>): Promise<void> {
        let {client_id, client_secret} = opts.getClientCredentials(req);
        let {code, redirect_uri, code_verifier} = req.body;

        // Check PKCE parameter
        if (opts.usePKCE && !code_verifier)
            return errorBody(res, TokenErrorRequest.INVALID_REQUEST, 'Missing code verifier')

        // Token verification
        let authCodePayload: any = verifyToken(code, opts.secret);
        if (!authCodePayload)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Authorization code is not valid or has expired');

        // Payload verification
        if (authCodePayload.client_id !== client_id)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Authorization code does not belong to the client');

        // Do database request at last to lessen db costs.
        if (!(await opts.validateClient(client_id, client_secret)))
            return errorBody(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        // Database verification
        let dbCode = await opts.tokenHandler.getAuthorizationCode({
            clientId: client_id,
            authorizationCode: code,
            user: authCodePayload.user,
        });

        if (!dbCode || dbCode.authorizationCode !== code)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Authorization code is not valid or has expired');

        if (redirect_uri !== dbCode.redirectUri)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Redirect URI is not the same that was used during authorization code grant');

        // Check PKCE
        if (opts.usePKCE) {
            if (dbCode.codeChallenge !== codeChallengeHash((dbCode.codeChallengeMethod as any), code_verifier))
                return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Code verifier is not valid');
        }

        // Database delete
        await opts.tokenHandler.deleteAuthorizationCode({
            clientId: client_id,
            authorizationCode: code,
            user: authCodePayload.user,
        });

        // Generate access & refresh tokens
        let response = await generateARTokens({
            client_id,
            user: authCodePayload.user,
            scopes: authCodePayload.scopes
        }, req, opts);
        res.status(200).header('Cache-Control', 'no-store').json(response);
    }

    private static async resourceOwnerCredentials(req: any, res: any, opts: Partial<ServerOptions>, scopes: string[]): Promise<void> {
        let {client_id, client_secret} = opts.getClientCredentials(req);
        let {username, password} = req.body;

        // Do database request at last to lessen db costs.
        if (!(await opts.validateClient(client_id, client_secret)))
            return errorBody(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        let user = await opts.validateUser(username, password);
        if (!user) return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Client authentication failed');

        let payload = {client_id, user, scopes};
        // Generate access & refresh tokens
        let response = await generateARTokens(payload, req, opts);
        res.status(200).header('Cache-Control', 'no-store').json(response);
    }

    private static async clientCredentials(req: any, res: any, opts: Partial<ServerOptions>, scopes: string[]): Promise<void> {
        let {client_id, client_secret} = opts.getClientCredentials(req);

        // Do database request at last to lessen db costs.
        if (!(await opts.validateClient(client_id, client_secret)))
            return errorBody(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        // Generate access & refresh tokens
        let response = await generateARTokens({client_id, scopes}, req, opts, false);
        res.status(200).header('Cache-Control', 'no-store').json(response);
    }

    private static async refreshToken(req: any, res: any, opts: Partial<ServerOptions>): Promise<void> {
        let {client_id, client_secret} = opts.getClientCredentials(req);
        let {scope, refresh_token} = req.body;
        if (!client_id) client_id = req.body.client_id;

        let refreshTokenPayload: any = verifyToken(refresh_token, opts.secret);
        if (!refreshTokenPayload)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Refresh token is not valid');

        // Check scopes - No need to check with app because the new scopes must
        // be subset of the refreshTokenPayload.scopes
        let scopes: string[] | null = scope.split(opts.scopeDelimiter);
        if (refreshTokenPayload.scopes.some(v => !scopes.includes(v)))
            return errorBody(res, TokenErrorRequest.INVALID_SCOPE, 'One or more scopes are not acceptable');

        if (refreshTokenPayload.client_id !== client_id)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Refresh token does not belong to client');

        // If client_secret was passed then verify client (else it will be verified by the access token).
        if (client_secret && !(await opts.validateClient(client_id, client_secret)))
            return errorBody(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        let dbToken = await opts.tokenHandler.getRefreshToken({
            refreshToken: refresh_token,
            clientId: client_id,
            user: refreshTokenPayload.user,
        });

        if (!dbToken || dbToken !== refresh_token)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Refresh token is not valid');

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
    public authorize(options: Partial<ServerOptions>): ExpressMiddleware {
        const opts = mergeOptions(this.options, options);
        checkOptions(opts, 'authorize');

        return async (req, res, next) => {
            if (req.method !== 'GET') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {client_id, redirect_uri, state, scope, response_type} = req.query;

            // Validate client_id and redirect_uri
            if (!opts.allowNonHTTPSRedirectURIs && !redirect_uri.startsWith('https://'))
                return errorBody(res, TokenErrorRequest.INVALID_REQUEST, 'Redirect URI is not https.');
            if (!(await opts.validateRedirectURI(client_id, redirect_uri))) // TODO - send grant type to check if client is allowed to use the specific grand type
                return errorBody(res, TokenErrorRequest.INVALID_REQUEST, 'Client id or redirect URI are not registered');

            let user: any
            if ((user = opts.getUser(req)) == null)
                return errorRedirect(res, AuthorizeErrorRequest.ACCESS_DENIED, redirect_uri, state, 'User did not approve request')

            /// Check state minimum length.
            if (state.length < opts.minStateLength)
                return errorRedirect(res, AuthorizeErrorRequest.INVALID_REQUEST, redirect_uri, state, `state must be at least ${opts.minStateLength} characters`)

            let gt: GrantTypes | null = getGrantType(response_type);
            if (!gt || !opts.grantTypes.includes(gt))
                return errorRedirect(res, AuthorizeErrorRequest.UNSUPPORTED_RESPONSE_TYPE, redirect_uri, state, 'response_type is not acceptable');

            // Validate scopes
            let scopes: string[] | null;
            if ((scopes = await parseScopes(scope, opts)) == null)
                return errorRedirect(res, AuthorizeErrorRequest.INVALID_SCOPE, redirect_uri, state, 'One or more scopes are not acceptable');

            if (response_type === 'code')
                Server.authorizationCode1(req, res, opts, scopes, user);
            else if (response_type === 'token')
                Server.implicit(req, res, opts, scopes, user);
            else
                errorRedirect(res, AuthorizeErrorRequest.UNSUPPORTED_RESPONSE_TYPE, redirect_uri, state, 'response_type is not acceptable');

        };
    }

    /**
     * Assign this function to the 'token' endpoint.
     */
    public token(options: Partial<ServerOptions>): ExpressMiddleware {
        const opts = mergeOptions(this.options, options);
        checkOptions(opts, 'token');

        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {grant_type, scope} = req.body;

            let gt: GrantTypes | null = getGrantType(grant_type);
            if (!gt || !opts.grantTypes.includes(gt))
                return errorBody(res, TokenErrorRequest.UNSUPPORTED_GRANT_TYPE, 'grant_type is not acceptable');

            if (grant_type === 'password' || grant_type === 'client_credentials') {
                // Check scopes
                let scopes: string[] | null;
                if ((scopes = await parseScopes(scope, opts)) == null)
                    return errorBody(res, TokenErrorRequest.INVALID_SCOPE, 'One or more scopes are not acceptable');

                if (grant_type === 'password')
                    Server.resourceOwnerCredentials(req, res, opts, scopes);
                else if (grant_type === 'client_credentials')
                    Server.clientCredentials(req, res, opts, scopes);

            } else if (grant_type === 'authorization_code')
                Server.authorizationCode2(req, res, opts);
            else if (grant_type === 'refresh_token')
                Server.refreshToken(req, res, opts);
            else
                return errorBody(res, TokenErrorRequest.UNSUPPORTED_GRANT_TYPE, 'grant_type is not acceptable');
        };
    }

    /**
     * Authenticate request.
     * @param options
     * @param scope The scopes needed for this request. If the access token scopes are insufficient
     *                  then the authentication will fail.
     */
    public authenticate(options: Partial<ServerOptions>, scope?: string | string[]): ExpressMiddleware {
        const opts = mergeOptions(this.options, options);
        checkOptions(opts, 'authenticate');

        let scopes: string[] = Array.isArray(scope) ? scope : scope?.split(/, */);
        return async (req, res, next) => {
            let token = opts.getToken(req);
            if (!token) {
                res.status(403).end('Authentication failed.')
                return;
            }

            let payload: any = verifyToken(token, opts.secret);
            if (!payload) {
                res.status(403).end('Authentication failed.')
                return;
            }

            if (scopes && payload.scopes.some(v => !scopes.includes(v))) {
                res.status(403).end('Authentication failed.')
                return;
            }

            let dbToken = await opts.tokenHandler.getAccessToken({
                accessToken: token,
                clientId: payload.client_id,
                user: payload.user
            });

            if (!dbToken || dbToken !== token) {
                res.status(403).end('Authentication failed.')
                return;
            }

            opts.setPayloadLocation(req, {
                clientId: payload.client_id,
                user: payload.user,
                scopes: payload.scopes,
            });
            next();
        };
    }
}