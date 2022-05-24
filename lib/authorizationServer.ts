import {ExpressMiddleware} from "./components/types";
import {buildRedirectURI, isEmbeddedWebView} from "./modules/utils";
import {verifyToken} from './modules/tokenUtils'
import {Implementation} from "./components/implementation";
import {AuthorizationServerOptions} from "./components/options/authorizationServerOptions";

export class AuthorizationServer {

    // TODO - add event listeners, maybe using .on(event, listener);
    //      - Add listener for invalid refreshToken to check if token is stolen etc (for clients without a secret)
    //      - Add listener if authorization code is used twice (it should be treated as an attack and if possible revoke tokens)
    //      - https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/

    // TODO - Maybe add like google device: https://www.oauth.com/oauth2-servers/device-flow/

    // TODO - Add a way to identify if scopes are valid with client_id & user_id (maybe pass req, that contains query and user)
    //      - This also can be checked before authorization at previous middleware by parsing and checking scopes

    // TODO - https://stackoverflow.com/questions/5925954/what-are-bearer-tokens-and-token-type-in-oauth-2

    // TODO - Add a custom function that will do extra checks the user wants.

    // TODO - Add checks for scopes when authorizing client (client may not be allowed to access specific scopes)

    // TODO - Add option to do all checks asynchronous with Promise.all([w1, w2, w3]).spread(function (r1, r2, r3) {})

    private readonly options: AuthorizationServerOptions;
    private readonly implementations: Implementation[] = [];
    private issueRefreshToken: boolean = false;

    constructor(options: AuthorizationServerOptions) {
        let opts: AuthorizationServerOptions = options;

        if (!opts.getToken)
            opts.getToken = (req) => req.headers['authorization']?.split(' ')?.[1];

        if (!opts.setPayloadLocation)
            opts.setPayloadLocation = (req, payload) => req.payload = payload;

        if (typeof opts.accessTokenLifetime !== 'undefined') {
            if (opts.accessTokenLifetime <= 0 || Math.trunc(opts.accessTokenLifetime) !== opts.accessTokenLifetime)
                throw new Error('accessTokenLifetime is not positive integer.')
        } else opts.accessTokenLifetime = 86400;

        if (typeof opts.refreshTokenLifetime === 'undefined')
            opts.refreshTokenLifetime = 864000;
        else if (opts.refreshTokenLifetime <= 0 || Math.trunc(opts.refreshTokenLifetime) !== opts.refreshTokenLifetime)
            throw new Error('refreshTokenLifetime is not positive integer.')

        if (typeof opts.isTemporaryUnavailable === 'undefined')
            opts.isTemporaryUnavailable = false;

        if (typeof opts.rejectEmbeddedWebViews === 'undefined')
            opts.rejectEmbeddedWebViews = true;

        if (typeof opts.isGrantTypeAllowed === 'undefined')
            opts.isGrantTypeAllowed = (client_id) => true;

        if (typeof opts.scopeDelimiter === 'undefined')
            opts.scopeDelimiter = ' ';

        this.options = opts;
    }

    public use(implementation: Implementation | Implementation[]): AuthorizationServer {
        let imps = Array.isArray(implementation) ? implementation : [implementation];

        imps.forEach(imp => {
            // Name check
            if (!imp.name)
                throw new Error('Implementation name is missing');

            // Endppoint check
            if (imp.endpoint !== 'token' && imp.endpoint !== 'authorize')
                throw new Error(`Implementation ${imp.name} has invalid endpoint`);

            // Response or grant type check
            if (typeof imp.matchType !== 'string')
                throw new Error('Implementation match type is not valid');
            if (imp.matchType.trim().length === 0)
                console.log(`Implementation ${imp.name} has empty match type which is not recommended`);

            // Match type duplication check for each endpoint
            let i;
            if ((i = imps.find(i => i.endpoint === imp.endpoint && i.matchType === imp.matchType)) != null)
                throw new Error(`Implementation ${imp.name} has the same match type as ${i.matchType}`);

            if (typeof imp.function !== 'function')
                throw new Error(`Implementation ${imp.name} has invalid function`);

            if (imp.name === 'refresh-token')
                this.issueRefreshToken = true;

            this.implementations.push(imp)
        });

        return this;
    }

    /**
     * Assign this function to the 'authorize' endpoint.
     */
    public authorize(): ExpressMiddleware {
        function error(res: any, err: string, redirectUri: string, state: string, description: string): void {
            description = description.endsWith('.') ? description : `${description}.`;
            res.header('WWW-Authenticate', `Bearer error=${err} error_description=${description}`)
                .redirect(buildRedirectURI(redirectUri, {
                    error: err,
                    error_description: description,
                    error_uri: 'Please check the docs for more information',
                    state
                }));
        }

        return async (req, res, next) => {
            if (req.method !== 'GET') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {client_id, redirect_uri, state, scope, response_type} = req.query;

            // Validate client_id and redirect_uri
            if (!(await this.options.validateRedirectURI(client_id, redirect_uri))) {
                let err = 'invalid_request';
                let description = 'Client id or redirect URI are not registered';
                res.status(400)
                    .header('WWW-Authenticate', `Bearer error=${err}`)
                    .header('WWW-Authenticate', `error_description=${description}`)
                    .json({
                        error: err,
                        error_description: 'description',
                        error_uri: 'Please check the docs for more information.'
                    });
                return;
            }

            if ((typeof this.options.isTemporaryUnavailable === 'boolean' ? this.options.isTemporaryUnavailable : await this.options.isTemporaryUnavailable(req)))
                return error(res, 'temporary_unavailable', redirect_uri, state, 'The authorization server is temporary unavailable.')

            if (this.options.rejectEmbeddedWebViews && isEmbeddedWebView(req))
                return error(res, 'invalid_request', redirect_uri, state, 'The request was made from an embedded web view, which is not allowed.')

            let user: any;
            if ((user = this.options.getUser(req)) == null)
                return error(res, 'access_denied', redirect_uri, state, 'User did not approve request')

            let imp = this.implementations.find(imp => imp.endpoint === 'authorize' && imp.matchType === response_type);
            if (!imp)
                return error(res, 'unsupported_response_type', redirect_uri, state, 'response_type is not supported');

            if (!(await this.options.isGrantTypeAllowed(client_id, imp.matchType)))
                return error(res, 'unauthorized_client', redirect_uri, state, 'This client is not allowed to use this grant type')

            // Validate scopes
            let scopes: string[] = scope?.split(this.options.scopeDelimiter) || [];
            if (!(await this.options.isScopesValid(scopes)))
                return error(res, 'invalid-scope', redirect_uri, state, 'One or more scopes are not acceptable');

            imp.function(req, {...this.options}, this.issueRefreshToken, (response, err) => {
                let r: any = err ? err : response;
                r.state = state;

                if (err) {
                    r.error_uri = r.error_uri ? r.error_uri : this.options.errorUri;
                    delete r.status;
                } else {
                    res.header('Cache-Control', 'no-store');
                }
                res.redirect(buildRedirectURI(redirect_uri, {...r, state}));
            }, scopes, user);
        };
    }

    /**
     * Assign this function to the 'token' endpoint.
     */
    public token(): ExpressMiddleware {
        function error(res: any, err: string, description: string): void {
            let status = 400;
            if (err === 'invalid_client')
                status = 401;

            description = description.endsWith('.') ? description : `${description}.`;
            res.status(status)
                .header('WWW-Authenticate', `Bearer error=${err} error_description=${description}`)
                .json({
                    error: err,
                    error_description: description,
                    error_uri: 'Please check the docs for more information.'
                });
        }

        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {grant_type} = req.body;

            let imp = this.implementations.find(imp => imp.endpoint === 'token' && imp.matchType === grant_type);
            if (!imp)
                return error(res, 'unsupported_grant_type', 'grant_type is not acceptable');

            imp.function(req, {...this.options}, this.issueRefreshToken, (response, err) => {
                if (err) {
                    res.status(err.status || 400);
                    delete err.status;
                    err.error_uri = err.error_uri ? err.error_uri : this.options.errorUri;
                    res.json(err);
                    return;
                }

                res.status(200).header('Cache-Control', 'no-store').json(response);
            }, undefined, undefined);
        };
    }

    /**
     * This function will be used to authenticate a request if the resource and authorization server
     * are one and the same. If they are different checkout the introspection endpoint.
     * @param scope The scopes needed for this request. If the access token scopes are insufficient
     *              then the authentication will fail. If scope is not initialized then the scope
     *              check will be omitted.
     */
    public authenticate(scope?: string | string[]): ExpressMiddleware {
        function error(res: any, err: string, description: string): void {
            let status = 0;
            switch (err) {
                case 'invalid_request':     status = 400; break;
                case 'invalid_token':       status = 401; break;
                case 'insufficient_scope':  status = 403; break;
            }

            description = description.endsWith('.') ? description : `${description}.`;
            res.status(status)
                .header('WWW-Authenticate', `Bearer error=${err} error_description=${description}`)
                .json({
                    error: err,
                    error_description: description,
                    error_uri: 'Please check the docs for more information.'
                });
        }

        let scopes: string[] | null = Array.isArray(scope) ? scope : scope?.split(/, */);
        return async (req, res, next) => {
            let token = this.options.getToken(req);
            if (!token)
                return error(res, 'invalid_request', 'No access token was provided');

            let payload: any = verifyToken(token, this.options.secret);
            if (!payload)
                return error(res, 'invalid_token', 'The access token expired');

            if (scopes && payload.scopes.some(v => !scopes.includes(v)))
                return error(res, 'insufficient_scope', 'Scopes re insufficient');

            let dbToken = await this.options.getAccessToken({
                accessToken: token,
                clientId: payload.client_id,
                user: payload.user
            });

            if (!dbToken || dbToken !== token)
                return error(res, 'invalid_token', 'The access token expired');

            this.options.setPayloadLocation(req, {
                clientId: payload.client_id,
                user: payload.user,
                scopes: payload.scopes,
            });
            next();
        };
    }

    /**
     * Assign this function to the 'introspection' endpoint.
     * This endpoint is meant to be accessible only by the resource servers, if you make this endpoint
     * public make sure to verify the client on your own before the request reach this function.
     */
    public introspection(): ExpressMiddleware {
        const inactive = (res): void => {
            res.status(200).json({active: false});
        }

        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {token} = req.body;
            if (!token) return inactive(res);

            let payload: any = verifyToken(token, this.options.secret);
            if (!payload) return inactive(res);

            let dbToken = await this.options.getAccessToken({
                accessToken: token,
                clientId: payload.client_id,
                user: payload.user
            });

            if (!dbToken || dbToken !== token)
                return inactive(res);

            res.status(200).json({
                active: true,
                scope: payload.scopes.join(this.options.scopeDelimiter),
                client_id: payload.client_id,
                user: payload.user,
                exp: payload.exp
            });
        }
    }
}