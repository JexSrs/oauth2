import {Flow} from "../../components/flow";
import {generateARTokens, getTokenExpiresAt} from "../../utils/tokenUtils";
import {ClientCredentialsOptions} from "./ccOptions.js";
import {Events} from "../../components/events";

export function clientCredentials(opts?: ClientCredentialsOptions): Flow {
    const options = Object.assign({}, opts);

    return {
        name: 'client-credentials',
        endpoint: 'token',
        matchType: 'client_credentials',
        function: async (data, callback, eventEmitter) => {
            const {scope} = data.req.body;

            // Validate scopes
            let scopes = scope?.split(' ') || [];
            if (!(await data.serverOpts.validateScopes(scopes, data.req))) {
                eventEmitter.emit(Events.INVALID_SCOPES, data.req);
                return callback(undefined, {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable',
                    error_uri: options.errorUri
                });
            }

            // Generate access token
            let tokens = await generateARTokens(data.req, {}, data.clientId, scopes, data.serverOpts, false);

            // Save to database
            let dbRes = await data.serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.accessTokenLifetime!, 'access'),
                clientId: data.clientId,
                scopes,
            }, data.req);

            if (!dbRes) {
                eventEmitter.emit(Events.FAILED_TOKEN_SAVE, data.req);
                return callback(undefined, {
                    error: 'server_error',
                    error_description: 'Encountered an unexpected error',
                    error_uri: options.errorUri
                });
            }

            // Respond with access token
            callback(tokens);
        }
    }
}