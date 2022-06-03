import {Implementation} from "../components/implementation";
import {generateARTokens, verifyToken, getTokenExpiresAt} from "../modules/tokenUtils";
import {RefreshTokenOptions} from "../components/options/implementations/refreshTokenOptions";
import {defaultCommonOpts} from "../modules/utils";

export function refreshToken(options: RefreshTokenOptions): Implementation {
    let opts = {...options, ...defaultCommonOpts(options)};

    if(typeof opts.getRefreshToken !== 'function')
        throw new Error('getRefreshToken is not a function');
    if(typeof opts.deleteTokens !== 'function')
        throw new Error('deleteTokens is not a function');

    return {
        name: 'refresh-token',
        endpoint: 'token',
        matchType: 'refresh_token',
        function: async (req, serverOpts, issueRefreshToken, callback) => {
            let {client_id, client_secret} = (serverOpts.getClientCredentials as any)(req);
            let {scope, refresh_token} = req.body;
            if (!client_id) client_id = req.body.client_id;

            if(!refresh_token)
                return callback(undefined, {
                    error: 'invalid_request',
                    error_description: 'Property refresh_token is missing'
                });

            // Verify refresh token
            let refreshTokenPayload: any = verifyToken(refresh_token, serverOpts.secret);
            if (!refreshTokenPayload)
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'The refresh token has expired'
                });

            if(refreshTokenPayload.type !== 'refresh_token')
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'Provided token is not a refresh token'
                });

            // Check scopes - No need to check with app because the new scopes must
            // be subset of the refreshTokenPayload.scopes
            let scopes: string[] = scope.split(serverOpts.scopeDelimiter);
            if (refreshTokenPayload.scopes.some((v: any) => !scopes.includes(v)))
                return callback(undefined, {
                    error: 'invalid_scope',
                    error_description: 'One or more scopes are not acceptable'
                });

            // Verify refresh token payload
            if (refreshTokenPayload.client_id !== client_id)
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: `This refresh token does not belong to client ${client_id}`
                });

            // Validate client
            if (!(await opts.validateClient(client_id, client_secret)))
                return callback(undefined, {
                    error: 'unauthorized_client',
                    error_description: 'Client authentication failed'
                });

            // Validate database
            let dbToken = await opts.getRefreshToken({
                refreshToken: refresh_token,
                clientId: client_id,
                user: refreshTokenPayload.user,
            });

            if (!dbToken || dbToken !== refresh_token)
                return callback(undefined, {
                    error: 'invalid_grant',
                    error_description: 'The refresh token has expired'
                });

            // Remove old tokens from database
            await opts.deleteTokens({
                refreshToken: refresh_token,
                clientId: client_id,
                user: refreshTokenPayload.user
            });

            // Generate new tokens
            let tokens = await generateARTokens({
                user: refreshTokenPayload.user
            }, client_id, scopes, serverOpts, true);

            // Database save
            let dbRes = await serverOpts.saveTokens({
                accessToken: tokens.access_token,
                accessTokenExpiresAt: getTokenExpiresAt(tokens, serverOpts.accessTokenLifetime!, 'access'),
                refreshToken: tokens.refresh_token,
                refreshTokenExpiresAt: getTokenExpiresAt(tokens, serverOpts.refreshTokenLifetime!, 'refresh'),
                clientId: client_id,
                user: refreshTokenPayload.user,
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