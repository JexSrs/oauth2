import {Implementation} from "../components/implementation";
import {generateARTokens, signToken, verifyToken} from "../modules/tokenUtils";
import {codeChallengeHash, defaultCommonOpts} from "../modules/utils";
import {AuthorizationCodeOptions} from "../components/options/implementations/authorizationCodeOptions";

export function authorizationCode(options: AuthorizationCodeOptions): Implementation[] {
    let opts = {...options, ...defaultCommonOpts(options)};

    if(opts.usePKCE === undefined)
        opts.usePKCE = true;

    if(opts.allowCodeChallengeMethodPlain === undefined)
        opts.allowCodeChallengeMethodPlain = true

    if(opts.authorizationCodeLifetime === undefined)
        opts.authorizationCodeLifetime = 60;
    else if (typeof opts.authorizationCodeLifetime !== 'number'
        || opts.authorizationCodeLifetime <= 0
        || Math.trunc(opts.authorizationCodeLifetime) !== opts.authorizationCodeLifetime)
        throw new Error('authorizationCodeLifetime is not positive integer.');

    if(typeof opts.saveAuthorizationCode !== 'function')
        throw new Error('saveAuthorizationCode is not a function');

    if(typeof opts.getAuthorizationCode !== 'function')
        throw new Error('getAuthorizationCode is not a function');

    if(typeof opts.deleteAuthorizationCode !== 'function')
        throw new Error('deleteAuthorizationCode is not a function');

    if(typeof opts.getIDTokenContent !== 'function')
        opts.getIDTokenContent = (user: any) => null;

    return [
        {
            name: 'authorization-code',
            endpoint: 'authorize',
            matchType: 'code',
            function: async (req, serverOpts, issueRefreshToken, callback, scopes, user) => {
                let {client_id, redirect_uri, code_challenge, code_challenge_method} = req.query;

                // Check for PKCE
                if (opts.usePKCE) {
                    if (!code_challenge)
                        return callback(undefined, {
                            error: 'invalid_request',
                            error_description: 'Query parameter code_challenge is missing',
                        });
                    if (!code_challenge_method)
                        return callback(undefined, {
                            error: 'invalid_request',
                            error_description: 'Query parameter code_challenge_method is missing',
                        });
                    if (!['S256', 'plain'].includes(code_challenge_method) || (code_challenge_method === 'plain' && !opts.allowCodeChallengeMethodPlain))
                        return callback(undefined, {
                            error: 'invalid_request',
                            error_description: 'Code challenge method is not valid',
                        });
                }

                // Generate authorization code
                let payload = {client_id, user};
                let code = signToken(payload, serverOpts.secret, opts.authorizationCodeLifetime);

                // Save authorization code to database
                let dbRes = await opts.saveAuthorizationCode({
                    authorizationCode: code,
                    expiresAt: Math.trunc((Date.now() + opts.authorizationCodeLifetime * 1000) / 1000),
                    clientId: client_id,
                    redirectUri: redirect_uri,
                    user,
                    scopes,
                    codeChallenge: code_challenge,
                    codeChallengeMethod: code_challenge_method
                });
                if(!dbRes)
                    return callback(undefined, {
                        error: 'server_error',
                        error_description: 'Encountered an unexpected error',
                    });

                // Respond with authorization code
                callback({code});
            }
        },
        {
            name: 'authorization-code',
            endpoint: 'token',
            matchType: 'authorization_code',
            function: async (req, serverOpts, issueRefreshToken, callback) => {
                let {client_id, client_secret} = (serverOpts.getClientCredentials as any)(req);
                let {code, redirect_uri, code_verifier} = req.body;
                if (client_id.length === 0) client_id = req.body.client_id;

                if (!code)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Property code is missing'
                    });

                if (!redirect_uri)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Property redirect_uri is missing'
                    });

                if (opts.usePKCE && !code_verifier)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Property code_verifier is missing'
                    });

                // Token verification
                let authCodePayload: any = verifyToken(code, serverOpts.secret);
                if (!authCodePayload)
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: 'The authorization code has expired'
                    })

                // Payload verification
                if (authCodePayload.client_id !== client_id)
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: `This authorization code does not belong to client ${client_id}`
                    });

                // Client validation
                if (!(await opts.validateClient(client_id, client_secret)))
                    return callback(undefined, {
                        error: 'unauthorized_client',
                        error_description: 'Client authentication failed'
                    });

                // Database verification
                let dbCode = await opts.getAuthorizationCode({
                    clientId: client_id,
                    authorizationCode: code,
                    user: authCodePayload.user
                });

                if (!dbCode || dbCode.authorizationCode !== code)
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: 'The authorization code has expired'
                    });

                // Check if redirect uri is the same that was generated on authorization code
                if (redirect_uri !== dbCode.redirectUri)
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: 'Redirect URI does not match the one that was used during authorization'
                    });

                // Check PKCE
                if (opts.usePKCE) {
                    if (dbCode.codeChallenge !== codeChallengeHash(dbCode.codeChallengeMethod, code_verifier))
                        return callback(undefined, {
                            error: 'invalid_grant',
                            error_description: 'Client failed PKCE verification'
                        });
                }

                // Database delete
                await opts.deleteAuthorizationCode({
                    clientId: client_id,
                    authorizationCode: code,
                    user: dbCode.user
                });

                // Generate access & refresh tokens
                let tokens = await generateARTokens({
                    user: dbCode.user
                }, client_id, dbCode.scopes, serverOpts, issueRefreshToken);

                // Database save
                let dbRes = await serverOpts.saveTokens({
                    accessToken: tokens.access_token,
                    accessTokenExpiresAt: tokens.expires_in ? Math.trunc((Date.now() + serverOpts.accessTokenLifetime! * 1000) / 1000) : undefined,
                    refreshToken: tokens.refresh_token,
                    refreshTokenExpiresAt: tokens.refresh_token ? Math.trunc((Date.now() + serverOpts.refreshTokenLifetime! * 1000) / 1000) : undefined,
                    clientId: client_id,
                    user: dbCode.user,
                    scopes: dbCode.scopes,
                });

                if(!dbRes)
                    return callback(undefined, {
                        error: 'server_error',
                        error_description: 'Encountered an unexpected error'
                    });

                // Generate ID token
                let idToken = await opts.getIDTokenContent(dbCode.user);
                if(idToken != null)
                    (tokens as any)['id_token'] = signToken(idToken, serverOpts.secret);

                // Respond with tokens
                callback(tokens);
            }
        }
    ]
}