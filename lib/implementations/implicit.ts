import {Implementation} from "../components/implementation";
import {generateARTokens} from "../modules/tokenUtils";

export function implicit(): Implementation {
    return {
        name: 'authorization-code',
        endpoint: 'authorize',
        matchType: 'token',
        function: async (req, serverOpts, issueRefreshToken, callback, scopes, user) => {
            let {client_id} = req.query;

            // Generate access token
            let tokens = await generateARTokens({user}, client_id, scopes, serverOpts, false);

            // Database save
            let dbRes = await serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: tokens.expires_in ? Math.trunc((Date.now() + serverOpts.accessTokenLifetime * 1000) / 1000) : undefined,
                clientId: client_id,
                user,
                scopes,
            });

            if(!dbRes)
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error'
                });

            callback(tokens);
        }
    }
}