import {Implementation} from "../components/implementation";
import {generateARTokens, getTokenExpiresAt} from "../modules/tokenUtils";
import {Events} from "../components/events";

export function implicit(): Implementation {
    return {
        name: 'authorization-code',
        endpoint: 'authorize',
        matchType: 'token',
        function: async (data, callback, eventEmitter) => {
            let {client_id} = data.req.query;

            // Generate access token
            let tokens = generateARTokens({user: data.user}, client_id, data.scopes!, data.serverOpts, false);

            // Database save
            let dbRes = await data.serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.accessTokenLifetime!, 'access'),
                clientId: client_id,
                user: data.user!,
                scopes: data.scopes!,
            });

            if(!dbRes) {
                eventEmitter.emit(Events.AUTHORIZATION_FLOWS_TOKEN_SAVE_ERROR, data.req);
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error'
                });
            }

            callback(tokens);
        }
    }
}