import {Implementation} from "../../components/implementation";
import {generateARTokens} from "../tokenUtils";
import {ClientCredentialsOptions} from "../../components/options/implementations/clientCredentialsOptions";
import {defaultOpts} from "../utils";

export function clientCredentials(options: ClientCredentialsOptions): Implementation {
    let opts: ClientCredentialsOptions = defaultOpts(options, 'client-credentials');
    return {
        name: 'client-credentials',
        endpoint: 'token',
        matchType: 'client_credentials',
        function: async (req, serverOpts, issueRefreshToken, callback) => {
            let {client_id, client_secret} = opts.getClientCredentials(req);
            const {scope} = req.body;

            let scopes = scope?.split(' ') || [];
            if (!(await serverOpts.isScopesValid(scopes)))
                return callback(undefined, {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable',
                    status: 400
                });

            if (!(await opts.validateClient(client_id, client_secret)))
                return callback(undefined, {
                    error: 'unauthorized_client',
                    error_description: 'Client authentication failed',
                    status: 400
                });

            // Generate access token
            let tokens = await generateARTokens({}, client_id, scopes, serverOpts, false);

            let dbRes = await serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: tokens.expires_in ? Math.trunc((Date.now() + serverOpts.accessTokenLifetime * 1000) / 1000) : undefined,
                clientId: client_id,
                scopes,
            });

            if(!dbRes)
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected database error'
                });

            callback(tokens);
        }
    }
}