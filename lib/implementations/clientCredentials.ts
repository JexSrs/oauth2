import {Implementation} from "../components/implementation";
import {generateARTokens} from "../modules/tokenUtils";
import {ClientCredentialsOptions} from "../components/options/implementations/clientCredentialsOptions";
import {defaultCommonOpts} from "../modules/utils";

export function clientCredentials(options: ClientCredentialsOptions): Implementation {
    let opts = {...options, ...defaultCommonOpts(options)};
    return {
        name: 'client-credentials',
        endpoint: 'token',
        matchType: 'client_credentials',
        function: async (req, serverOpts, issueRefreshToken, callback) => {
            let {client_id, client_secret} = (serverOpts.getClientCredentials as any)(req);
            const {scope} = req.body;

            // Validate scopes
            let scopes = scope?.split(' ') || [];
            if (!(await serverOpts.isScopesValid(scopes)))
                return callback(undefined, {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable'
                });

            // Validate client
            if (!(await opts.validateClient(client_id, client_secret)))
                return callback(undefined, {
                    error: 'unauthorized_client',
                    error_description: 'Client authentication failed'
                });

            // Generate access token
            let tokens = await generateARTokens({}, client_id, scopes, serverOpts, false);

            // Save to database
            let dbRes = await serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: tokens.expires_in ? Math.trunc((Date.now() + serverOpts.accessTokenLifetime! * 1000) / 1000) : undefined,
                clientId: client_id,
                scopes,
            });

            if(!dbRes)
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error'
                });

            // Respond with access token
            callback(tokens);
        }
    }
}