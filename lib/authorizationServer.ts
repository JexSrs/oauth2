import {ExpressMiddleware, OAuth2Error} from "./components/types";
import {buildRedirectURI, isEmbeddedWebView} from "./modules/utils";
import {verifyToken} from './modules/tokenUtils'
import {Implementation} from "./components/implementation";
import {AuthorizationServerOptions} from "./components/options/authorizationServerOptions";

export class AuthorizationServer {

    // TODO - add event listeners, maybe using .on(event, listener);
    //      - Add listener for invalid refreshToken to check if token is stolen etc (for clients without a secret)
    //      - Add listener if authorization code is used twice (it should be treated as an attack and if possible revoke tokens)
    //      - https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/

    // TODO - Add a way to identify if scopes are valid with client_id & user_id (maybe pass req, that contains query and user)
    //      - This also can be checked before authorization at previous middleware by parsing and checking scopes

    // TODO - https://stackoverflow.com/questions/5925954/what-are-bearer-tokens-and-token-type-in-oauth-2

    // TODO - Add a custom function that will do extra checks the user wants.

    // TODO - Add checks for scopes when authorizing client (client may not be allowed to access specific scopes)

    // TODO - Add option to do all checks asynchronous with Promise.all([w1, w2, w3]).spread(function (r1, r2, r3) {})

    // TODO - https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#endpoint

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
     * Recommended endpoint: /api/oauth/v2/authorize
     */
    public authorize(): ExpressMiddleware {
        function error(res: any, data: OAuth2Error & { redirect_uri?: string; state?: string; body?: boolean; }) {
            let wwwAuthHeader = `Bearer error=${data.error}`;
            if (data.error_description) wwwAuthHeader += ` error_description="${data.error_description}"`;
            if (data.error_uri) wwwAuthHeader += ` error_uri="${data.error_uri}"`;

            let resp = {
                error: data.error,
                error_description: data.error_description,
                error_uri: data.error_uri,
                state: data.state
            };

            res.header('Cache-Control', 'no-store')
                .header('WWW-Authenticate', wwwAuthHeader)

            if(data.body) res.json(resp)
            else res.redirect(buildRedirectURI(data.redirect_uri, resp));
        }

        return async (req, res, next) => {
            if (req.method !== 'GET') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {client_id, redirect_uri, state, scope, response_type} = req.query;

            if(!client_id)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Missing client id',
                });

            if(!redirect_uri)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Missing redirect uri'
                });

            if(!response_type)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'response_type redirect uri'
                });

            // Validate client_id and redirect_uri
            if (!(await this.options.validateRedirectURI(client_id, redirect_uri)))
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'Client id or redirect URI are not registered',
                    error_uri: this.options.errorUri,
                    body: true
                })

            if ((typeof this.options.isTemporaryUnavailable === 'boolean' ? this.options.isTemporaryUnavailable : await this.options.isTemporaryUnavailable(req)))
                return error(res, {
                    error: 'temporary_unavailable',
                    error_description: 'The authorization server is temporary unavailable',
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });

            if (this.options.rejectEmbeddedWebViews && isEmbeddedWebView(req))
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'The request was made from an embedded web view, which is not allowed',
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });

            let user: any;
            if ((user = this.options.getUser(req)) == null)
                return error(res, {
                    error: 'access_denied',
                    error_description: 'User did not approve request',
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });

            let imp = this.implementations.find(imp => imp.endpoint === 'authorize' && imp.matchType === response_type);
            if (!imp)
                return error(res, {
                    error: 'unsupported_response_type',
                    error_description: 'response_type is not supported',
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });

            if (!(await this.options.isGrantTypeAllowed(client_id, imp.matchType)))
                return error(res, {
                    error: 'unauthorized_client',
                    error_description: 'This client is not allowed to use this grant type',
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });

            // Validate scopes
            let scopes: string[] = scope?.split(this.options.scopeDelimiter) || [];
            if (!(await this.options.isScopesValid(scopes)))
                return error(res, {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable',
                    error_uri: this.options.errorUri,
                    redirect_uri,
                    state
                });

            imp.function(req, {...this.options}, this.issueRefreshToken, (response, err) => {
                if (err)
                    return error(res, {
                        error: 'invalid_scope',
                        error_description: err.error_description,
                        error_uri: err.error_uri || this.options.errorUri,
                        redirect_uri,
                        state
                    });

                res.header('Cache-Control', 'no-store')
                    .redirect(
                        buildRedirectURI(redirect_uri, {
                            ...response,
                            state
                        })
                    );
            }, scopes, user);
        };
    }

    /**
     * Assign this function to the 'token' endpoint.
     * Recommended endpoint: /api/oauth/v2/token
     */
    public token(): ExpressMiddleware {
        function error(res: any, data: OAuth2Error & {status?: number}) {
            let wwwAuthHeader = `Bearer error=${data.error}`;
            if (data.error_description) wwwAuthHeader += ` error_description="${data.error_description}"`;
            if (data.error_uri) wwwAuthHeader += ` error_uri="${data.error_uri}"`;

            res.status(data.status || 400)
                .header('WWW-Authenticate', wwwAuthHeader)
                .json({
                    error: data.error,
                    error_description: data.error_description,
                    error_uri: data.error_uri
                });
        }

        return async (req, res, next) => {
            if (req.method !== 'POST') {
                res.status(405).end('Method not allowed.');
                return;
            }

            const {grant_type} = req.body;

            if(!grant_type)
                return error(res, {
                    error: 'invalid_request',
                    error_description: 'grant_type redirect uri'
                });

            let imp = this.implementations.find(imp => imp.endpoint === 'token' && imp.matchType === grant_type);
            if (!imp)
                return error(res, {
                    error: 'unsupported_grant_type',
                    error_description: 'grant_type is not acceptable',
                    error_uri: this.options.errorUri
                });

            imp.function(req, {...this.options}, this.issueRefreshToken, (response, err) => {
                if(err)
                    return error(res, {
                        error: err.error,
                        error_description: err.error_description,
                        error_uri: err.error_uri ? err.error_uri : this.options.errorUri,
                        status: err.status
                    });

                res.header('Cache-Control', 'no-store')
                    .status(err ? err.status || 400 : 200)
                    .json(response);
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
                case 'invalid_request':
                    status = 400;
                    break;
                case 'invalid_token':
                    status = 401;
                    break;
                case 'insufficient_scope':
                    status = 403;
                    break;
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
     * Recommended endpoint: /api/oauth/v2/introspection
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
                exp: payload.exp,
                token_type: 'Bearer'
            });
        }
    }
}