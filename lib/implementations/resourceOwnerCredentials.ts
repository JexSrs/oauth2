import {Implementation} from "../components/implementation";
import {generateARTokens} from "../modules/tokenUtils";
import {ResourceOwnerCredentialsOptions} from "../components/options/implementations/resourceOwnerCredentialsOptions";
import {defaultCommonOpts} from "../modules/utils";

export function resourceOwnerCredentials(options: ResourceOwnerCredentialsOptions): Implementation {
    let opts = {...options, ...defaultCommonOpts(options)};

    if(typeof opts.validateUser !== 'function')
        throw new Error('validateUser is not a function');

    return {
        name: 'resource-owner-credentials',
        endpoint: 'token',
        matchType: 'password',
        function: async (req, serverOpts, issueRefreshToken, callback) => {
            let {client_id, client_secret} = (serverOpts.getClientCredentials as any)(req);
            const {scope, username, password} = req.body;

            if(!username)
                return callback(undefined, {
                    error: 'invalid_request',
                    error_description: 'Property username is missing'
                });

            if(!password)
                return callback(undefined, {
                    error: 'invalid_request',
                    error_description: 'Property password is missing'
                });

            let scopes = scope?.split(serverOpts.scopeDelimiter) || [];
            if (!(await serverOpts.isScopesValid(scopes)))
                return callback(undefined, {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable'
                });

            // Do database request at last to lessen db costs.
            if (!(await opts.validateClient(client_id, client_secret)))
                return callback(undefined, {
                    error: 'unauthorized_client',
                    error_description: 'Client authentication failed'
                });

            let user = await opts.validateUser(username, password);
            if (!user)
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'User authentication failed'
                });

            // Generate access & refresh tokens
            let tokens = await generateARTokens({user}, client_id, scopes, serverOpts, issueRefreshToken);

            // Database save
            let dbRes = await serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: tokens.expires_in ? Math.trunc((Date.now() + serverOpts.accessTokenLifetime * 1000) / 1000) : undefined,
                refreshToken: tokens.refresh_token,
                refreshTokenExpiresAt: tokens.refresh_token ? Math.trunc((Date.now() + serverOpts.refreshTokenLifetime * 1000) / 1000) : undefined,
                clientId: client_id,
                user,
                scopes,
            });

            if(!dbRes)
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error',
                });

            callback(tokens);
        }
    }
}