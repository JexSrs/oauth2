import {ServerOptions} from "./components/serverOptions";
import {ExpressMiddleware} from "./components/types";
import {
    buildRedirectURI,
    errorBody,
    errorRedirect,
    generateARTokens,
    getGrantType,
    hash,
    parseScopes,
    signToken,
    verifyToken
} from "./modules/utils";
import {memory} from "./modules/memory";
import {GrantTypes} from "./components/GrantTypes";
import {TokenErrorRequest} from "./components/tokenErrorRequest";
import {AuthorizeErrorRequest} from "./components/authorizeErrorRequest";


export class Server {

    // TODO - add event listeners, maybe using .on(event, listener);
    //      - Add listsner for invalid refreshToken to check if token is stolen etc (for clients without a secret).
    //      - https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/
    // TODO - add event middlewares, maybe using .use(event, listener);
    // TODO - add new implementation, maybe using .use('implementation', function)
    // TODO - add custom options for authorize & token (this will allow using the functions multiple times with different configuration)
    // TODO - https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/

    private readonly options: ServerOptions;

    constructor(options?: ServerOptions) {
        let opts: Partial<ServerOptions> = options || {};

        if (!opts.grantTypes)
            opts.grantTypes = [GrantTypes.AUTHORIZATION_CODE, GrantTypes.REFRESH_TOKEN];

        if (!opts.getToken)
            opts.getToken = (req) => req.headers['authorization'];

        if (!opts.payloadLocation)
            opts.payloadLocation = (req, payload) => req.payload = payload;

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

        if (!opts.getUserApproved)
            opts.getUserApproved = (req: any) => req.userApproved;

        if (!opts.scopeDelimiter)
            opts.scopeDelimiter = ' ';

        this.options = opts as ServerOptions;
    }

    private async authorizationCode1(req: any, res: any, scopes: string[]): Promise<void> {
        let {state, client_id, redirect_uri, code_challenge, code_challenge_method} = req.query;

        // Check for PKCE
        if (this.options.usePKCE) {
            if (!code_challenge)
                return errorRedirect(res, AuthorizeErrorRequest.INVALID_REQUEST, redirect_uri, state, 'Missing code challenge.')
            if (!['S256', 'plain'].includes(code_challenge_method) || (code_challenge_method === 'plain' && !this.options.allowCodeChallengeMethodPlain))
                return errorRedirect(res, AuthorizeErrorRequest.INVALID_REQUEST, redirect_uri, state, 'Code challenge method is not valid.')
        }

        // Get user from the application
        let user = this.options.getUser(req);

        // Generate authorization code
        let payload = {client_id, user};
        let code = signToken(payload, this.options.secret, this.options.authorizationCodeLifetime);

        // Save authorization code to database
        await this.options.tokenHandler.saveAuthorizationCode({
            authorizationCode: code,
            expiresAt: Math.trunc((Date.now() + this.options.authorizationCodeLifetime * 1000) / 1000),
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

    private async implicit(req: any, res: any, scopes: string[]): Promise<void> {
        let {state, scope, client_id, redirect_uri} = req.query;

        // Get user from the application
        let user = this.options.getUser(req);

        // Generate access & refresh tokens
        let payload = {client_id, user, scopes};
        let tokens = await generateARTokens(payload, scopes, req, this.options);

        // Respond with tokens
        res.header('Cache-Control', 'no-store').redirect(buildRedirectURI(redirect_uri, tokens));
    }

    private async authorizationCode2(req: any, res: any): Promise<void> {
        let {client_id, client_secret} = this.options.getClientCredentials(req);
        let {code, redirect_uri, code_verifier} = req.body;

        // Check PKCE parameter
        if (this.options.usePKCE && !code_verifier)
            return errorBody(res, TokenErrorRequest.INVALID_REQUEST, 'Missing code verifier')

        // Token verification
        let authCodePayload: any = verifyToken(code, this.options.secret);
        if (!authCodePayload)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Authorization code is not valid or has expired');

        // Payload verification
        if (authCodePayload.client_id !== client_id)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Authorization code does not belong to the client');

        // Do database request at last to lessen db costs.
        if (!(await this.options.validateClient(client_id, client_secret)))
            return errorBody(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        // Database verification
        let dbCode = await this.options.tokenHandler.getAuthorizationCode({
            clientId: client_id,
            authorizationCode: code,
            user: authCodePayload.user,
        });

        if (!dbCode || dbCode.authorizationCode !== code)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Authorization code is not valid or has expired');

        if (redirect_uri !== dbCode.redirectUri)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Redirect URI is not the same that was used during authorization code grant');

        // Check PKCE
        if (this.options.usePKCE) {
            if (dbCode.codeChallenge !== hash((dbCode.codeChallengeMethod as any), code_verifier))
                return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Code verifier is not valid');
        }

        // Database delete
        await this.options.tokenHandler.deleteAuthorizationCode({
            clientId: client_id,
            authorizationCode: code,
            user: authCodePayload.user,
        });

        // Generate access & refresh tokens
        let response = await generateARTokens({
            client_id,
            user: authCodePayload.user,
            scopes: authCodePayload.scopes
        }, authCodePayload.scopes, req, this.options);
        res.status(200).header('Cache-Control', 'no-store').json(response);
    }

    private async resourceOwnerCredentials(req: any, res: any, scopes: string[]): Promise<void> {
        let {client_id, client_secret} = this.options.getClientCredentials(req);
        let {username, password} = req.body;

        // Do database request at last to lessen db costs.
        if (!(await this.options.validateClient(client_id, client_secret)))
            return errorBody(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        let user = await this.options.validateUser(username, password);
        if(!user) return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Client authentication failed');

        let payload = {client_id, user, scopes};
        // Generate access & refresh tokens
        let response = await generateARTokens(payload, scopes, req, this.options);
        res.status(200).header('Cache-Control', 'no-store').json(response);
    }

    private async clientCredentials(req: any, res: any, scopes: string[]): Promise<void> {
        let {client_id, client_secret} = this.options.getClientCredentials(req);

        // Do database request at last to lessen db costs.
        if (!(await this.options.validateClient(client_id, client_secret)))
            return errorBody(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        // Generate access & refresh tokens
        let response = await generateARTokens({client_id, scopes}, scopes, req, this.options);
        delete response.refresh_token;
        delete response.refresh_token_expires_in;
        res.status(200).header('Cache-Control', 'no-store').json(response);
    }

    private async refreshToken(req: any, res: any): Promise<void> {
        let {client_id, client_secret} = this.options.getClientCredentials(req);
        let {scope, refresh_token} = req.body;
        if (!client_id) client_id = req.body.client_id;

        let refreshTokenPayload: any = verifyToken(refresh_token, this.options.secret);
        if (!refreshTokenPayload)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Refresh token is not valid');

        // Check scopes - No need to check with app because the new scopes must
        // be subset of the refreshTokenPayload.scopes
        let scopes: string[] | null = scope.split(this.options.scopeDelimiter);
        if (refreshTokenPayload.scopes.some(v => !scopes.includes(v)))
            return errorBody(res, TokenErrorRequest.INVALID_SCOPE, 'One or more scopes are not acceptable');

        if (refreshTokenPayload.client_id !== client_id)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Refresh token does not belong to client');

        // If client_secret was passed then verify client (else it will be verified by the access token).
        if (client_secret && !(await this.options.validateClient(client_id, client_secret)))
            return errorBody(res, TokenErrorRequest.UNAUTHORIZED_CLIENT, 'Client authentication failed');

        let dbToken = await this.options.tokenHandler.getRefreshToken({
            refreshToken: refresh_token,
            clientId: client_id,
            user: refreshTokenPayload.user,
        });

        if (!dbToken || dbToken !== refresh_token)
            return errorBody(res, TokenErrorRequest.INVALID_GRANT, 'Refresh token is not valid');

        // Remove old tokens from database
        await this.options.tokenHandler.deleteTokens({
            refreshToken: refresh_token,
            clientId: client_id,
            user: refreshTokenPayload.user
        });

        let response = await generateARTokens({client_id, scopes}, scopes, req, this.options);
        res.status(200).header('Cache-Control', 'no-store').json(response);
    }

    /**
     * Assign this function to the 'authorize' endpoint.
     */
    public authorize(): ExpressMiddleware {
        return async (req, res, next) => {
            if (req.method !== 'GET') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {client_id, redirect_uri, state, scope, response_type} = req.query;

            // Validate client_id and redirect_uri
            if (!this.options.allowNonHTTPSRedirectURIs && !redirect_uri.startsWith('https://'))
                return errorBody(res, TokenErrorRequest.INVALID_REQUEST, 'Redirect URI is not https.');
            if (!(await this.options.validateRedirectURI(client_id, redirect_uri))) // TODO - send grant type to check if client is allowed to use the specific grand type
                return errorBody(res, TokenErrorRequest.INVALID_REQUEST, 'Client id or redirect URI are not registered');

            if (!this.options.getUserApproved(req))
                return errorRedirect(res, AuthorizeErrorRequest.ACCESS_DENIED, redirect_uri, state, 'User did not approve request')

            /// Check state minimum length.
            if (state.length < this.options.minStateLength)
                return errorRedirect(res, AuthorizeErrorRequest.INVALID_REQUEST, redirect_uri, state, `state must be at least ${this.options.minStateLength} characters`)

            let gt: GrantTypes | null = getGrantType(response_type);
            if (!gt || !this.options.grantTypes.includes(gt))
                return errorRedirect(res, AuthorizeErrorRequest.UNSUPPORTED_RESPONSE_TYPE, req.params.redirect_uri, req.params.state, 'response_type is not acceptable');

            // Validate scopes
            let scopes: string[] | null;
            if ((scopes = await parseScopes(scope, gt, this.options)) == null)
                return errorRedirect(res, AuthorizeErrorRequest.INVALID_SCOPE, redirect_uri, state, 'One or more scopes are not acceptable');

            if (response_type === 'code')
                this.authorizationCode1(req, res, scopes);
            else if (response_type === 'token')
                this.implicit(req, res, scopes);
            else
                errorRedirect(res, AuthorizeErrorRequest.UNSUPPORTED_RESPONSE_TYPE, req.params.redirect_uri, req.params.state, 'response_type is not acceptable');

        };
    }

    /**
     * Assign this function to the 'token' endpoint.
     */
    public token(): ExpressMiddleware {
        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {grant_type, scope} = req.body;

            let gt: GrantTypes | null = getGrantType(grant_type);
            if (!gt || !this.options.grantTypes.includes(gt))
                return errorBody(res, TokenErrorRequest.UNSUPPORTED_GRANT_TYPE, 'grant_type is not acceptable');

            if (grant_type === 'password' || grant_type === 'client_credentials') {
                // Check scopes
                let scopes: string[] | null;
                if ((scopes = await parseScopes(scope, gt, this.options)) == null)
                    return errorBody(res, TokenErrorRequest.INVALID_SCOPE, 'One or more scopes are not acceptable');

                if (grant_type === 'password')
                    this.resourceOwnerCredentials(req, res, scopes);
                else if (grant_type === 'client_credentials')
                    this.clientCredentials(req, res, scopes);

            }
            else if (grant_type === 'authorization_code')
                this.authorizationCode2(req, res);
            else if (grant_type === 'refresh_token')
                this.refreshToken(req, res);
            else
                return errorBody(res, TokenErrorRequest.UNSUPPORTED_GRANT_TYPE, 'grant_type is not acceptable');
        };
    }

    /**
     * Authenticate request.
     * @param scope The scopes needed for this request. If the access token scopes are insufficient
     *                  then the authentication will fail.
     */
    public authenticate(scope?: string | string[]): ExpressMiddleware {
        let scopes: string[] = Array.isArray(scope) ? scope : scope?.split(/, */);
        return async (req, res, next) => {
            let token = this.options.getToken(req);
            if(!token) {
                res.status(403).end('Authentication failed.')
                return;
            }

            let payload: any = verifyToken(token, this.options.secret);
            if (!payload) {
                res.status(403).end('Authentication failed.')
                return;
            }

            if (scopes && payload.scopes.some(v => !scopes.includes(v))) {
                res.status(403).end('Authentication failed.')
                return;
            }

            let dbToken = await this.options.tokenHandler.getAccessToken({
                accessToken: token,
                clientId: payload.client_id,
                user: payload.user
            });

            if (!dbToken || dbToken !== token) {
                res.status(403).end('Authentication failed.')
                return;
            }

            this.options.payloadLocation(req, {
                clientId: payload.client_id,
                user: payload.user,
                scopes: payload.scopes,
            });
            next();
        };
    }
}