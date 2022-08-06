import {ResourceServerOptions} from "./components/resourceServerOptions.js";
import {ExpressMiddleware} from "./components/types";
import axios from "axios";
import {buildQuery, error} from "./utils/utils";
import {AuthorizationServerOptions} from "./components/authorizationServerOptions.js";

export class ResourceServer {

    private readonly options: Required<ResourceServerOptions>;

    constructor(options: ResourceServerOptions) {
        let opts: ResourceServerOptions = Object.assign({}, options);

        if (opts.getToken === undefined)
            opts.getToken = (req) => req.headers['authorization']?.split(' ')?.[1];

        if (opts.setPayloadLocation === undefined)
            opts.setPayloadLocation = (req, payload) => req.payload = payload;

        if(opts.headers === undefined)
            opts.headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            };
        if(opts.body === undefined)
            opts.body = {};

        if(opts.scopeDelimiter === undefined)
            opts.scopeDelimiter = ' ';

        ['introspectionURL', 'audience']
            .forEach(field => {
                if((opts as any)[field] === undefined) throw new Error(`Field ${field} cannot be undefined`);
            });

        this.options = opts as Required<ResourceServerOptions>;
    }

    /**
     * This function will be used to authenticate a request.
     * It will make a request to the authorization server to verify the validity of the access token.
     *
     * It is recommended to cache the response for this endpoint for short periods of time.
     *
     * @param scope The scopes needed for this request. If the access token scopes are insufficient
     *              then the authentication will fail. If scope is not initialized then the scope
     *              check will be omitted.
     * @param cond If more than one scopes are provided, whether the access token must have all of them
     *              or at least one of them.
     */
    public authenticate(scope?: string | string[], cond?: 'all' | 'some'): ExpressMiddleware {
        const options = Object.assign(this.options, {});

        let scopes: string[] | undefined = Array.isArray(scope) ? scope : (scope ? [scope] : undefined);
        let condition = cond || 'all';

        return (req, res, next) => {
            let token = options.getToken(req);

            axios.post(options.introspectionURL, buildQuery({
                ...options.body,
                token,
            }), {
                headers: <any>options.headers
            }).then(response => {
                const data = response.data;

                if(data.active === false)
                    return error(res, {
                        error: 'invalid_token',
                        error_description: 'The access token has expired',
                        error_uri: options.errorUri,
                        status: 401,
                        noCache: false
                    });

                if(data.aud !== options.audience)
                    return error(res, {
                        error: 'invalid_token',
                        error_description: 'The access token is not meant to be used in this resource server',
                        error_uri: options.errorUri,
                        status: 401,
                        noCache: false
                    });


                // Check scopes
                if(scopes) {
                    let dataScopes = data.scope.split(options.scopeDelimiter);
                    if(
                        (condition === 'all' && scopes.some((v: string) => !dataScopes!.includes(v)))
                        || (condition === 'some' && dataScopes.some((v: string) => !scopes!.includes(v)))
                    )
                        return error(res, {
                            error: 'insufficient_scope',
                            error_description: 'Client does not have access to this endpoint',
                            error_uri: options.errorUri,
                            status: 403,
                            noCache: false
                        });
                }

                options.setPayloadLocation(req, response.data)
                next();
            }).catch(e => {
                // Unexpected errors
                console.log(e);
                error(res, {
                    error: 'server_error',
                    error_description: 'Authorization server is not responding or is not reachable.',
                    error_uri: options.errorUri,
                    noCache: false,
                    status: 503
                })
            });
        };
    }

    public authenticateJWT(scope?: string | string[], cond?: 'all' | 'some'): ExpressMiddleware {
        const options = Object.assign(this.options, {});

        let scopes: string[] | undefined = Array.isArray(scope) ? scope : (scope ? [scope] : undefined);
        let condition = cond || 'all';

        // TODO - Authenticate using JWT and not introspection url (make introspectionURL or secret mandatory in options)
        //      - Merge two functions as one, put an 'if' before flow to check if introspectionURL or secret is defined)

        return (req, res, next) => {
            let token = options.getToken(req);

            // validate that header 'typ' is either `at+jwt` or 'application/at+jwt' (reject otherwise)
            // Validate 'iss', 'aud' claim
            // Reject if header 'alg' is 'none'. Throw invalid_token if any of the above is not valid

        };
    }
}