import {Flow} from "../../components/flow";
import {generateARTokens, getTokenExpiresAt} from "../../utils/tokenUtils";
import {Events} from "../../components/events";
import {ImplicitOptions} from "./implicitOptions";

export function implicit(opts?: ImplicitOptions): Flow {
    const options = Object.assign({}, opts);
    return {
        name: 'implicit',
        endpoint: 'authorize',
        matchType: 'token',
        function: async (data, callback, eventEmitter) => {

            // Generate access token
            let tokens = await generateARTokens(data.req, {user: data.user}, data.clientId, data.scopes!, data.serverOpts, false);

            // Database save
            let dbRes = await data.serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.accessTokenLifetime!, 'access'),
                clientId: data.clientId,
                user: data.user!,
                scopes: data.scopes!,
            }, data.req);

            if (!dbRes) {
                eventEmitter.emit(Events.FAILED_TOKEN_SAVE, data.req);
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error',
                    error_uri: options.errorUri
                });
            }

            callback(tokens);
        }
    }
}