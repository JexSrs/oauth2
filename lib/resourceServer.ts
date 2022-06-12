import {ResourceServerOptions} from "./components/options/resourceServerOptions";
import {ExpressMiddleware} from "./components/types";
import axios from "axios";
import {error} from "./modules/utils";

export class ResourceServer {

    private readonly options: Required<ResourceServerOptions>;

    constructor(opts: ResourceServerOptions) {
        if (!opts.getToken)
            opts.getToken = (req) => req.headers['authorization']?.split(' ')?.[1];

        if (!opts.setPayloadLocation)
            opts.setPayloadLocation = (req, payload) => req.payload = payload;

        if(!opts.introspectionHeaders)
            opts.introspectionHeaders = {};

        if(!opts.scopeDelimiter)
            opts.scopeDelimiter = ' ';

        this.options = opts as Required<ResourceServerOptions>;
    }

    /**
     * This function will be used to authenticate a request.
     * @param scope The scopes needed for this request. If the access token scopes are insufficient
     *              then the authentication will fail. If scope is not initialized then the scope
     *              check will be omitted.
     * @param cond If more than one scopes are provided, whether the access token must have all of them
     *              or at least one of them.
     */
    public authenticate(scope?: string | string[], cond?: 'all' | 'some'): ExpressMiddleware {
        let scopes: string[] | undefined = Array.isArray(scope) ? scope : (scope ? [scope] : undefined);
        let condition = cond || 'all';

        return (req, res, next) => {
            let token = this.options.getToken(req);

            axios.post(this.options.introspectionURL, {token}, {
                headers: this.options.introspectionHeaders as any
            }).then(response => {
                const data = response.data;

                if(data.active === false)
                    return error(res, {
                        error: 'invalid_token',
                        error_description: 'The access token has expired',
                        error_uri: this.options.errorUri,
                        status: 401,
                        noCache: false
                    });

                // Check scopes
                if(scopes) {
                    let dataScopes = data.scope.split(this.options.scopeDelimiter);
                    if(
                        (condition === 'all' && scopes.some((v: string) => !dataScopes!.includes(v)))
                        || (condition === 'some' && dataScopes.some((v: string) => !scopes!.includes(v)))
                    )
                        return error(res, {
                            error: 'insufficient_scope',
                            error_description: 'Client does not have access to this endpoint',
                            error_uri: this.options.errorUri,
                            status: 403,
                            noCache: false
                        });
                }

                this.options.setPayloadLocation(req, response.data)
                next();
            }).catch(e => {
                // Unexpected errors
                console.log(e);
                error(res, {
                    error: 'server_error',
                    error_description: 'Authorization server is not responding or is not reachable.',
                    error_uri: this.options.errorUri,
                    noCache: false,
                    status: 400
                })
            });
        };
    }
}