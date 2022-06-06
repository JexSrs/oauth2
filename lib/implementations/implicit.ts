import {Implementation} from "../components/implementation";
import {generateARTokens, getTokenExpiresAt} from "../modules/tokenUtils";
import {Events} from "../components/events";

export function implicit(): Implementation {
    return {
        name: 'authorization-code',
        endpoint: 'authorize',
        matchType: 'token',
        function: async (req, serverOpts, issueRefreshToken, callback, eventEmitter, scopes, user) => {
            let {client_id} = req.query;

            // Generate access token
            let tokens = await generateARTokens({user}, client_id, scopes!, serverOpts, false);

            // Database save
            let dbRes = await serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: getTokenExpiresAt(tokens, serverOpts.accessTokenLifetime!, 'access'),
                clientId: client_id,
                user,
                scopes: scopes!,
            });

            if(!dbRes) {
                eventEmitter.emit(Events.AUTHORIZATION_FLOWS_TOKEN_SAVE_ERROR, req);
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error'
                });
            }

            callback(tokens);
        }
    }
}