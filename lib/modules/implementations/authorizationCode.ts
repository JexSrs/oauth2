import {Implementation} from "../../components/implementation";
import {generateARTokens, signToken, verifyToken} from "../tokenUtils";
import {codeChallengeHash, defaultOpts} from "../utils";
import {AuthorizationCodeOptions} from "../../components/options/implementations/authorizationCodeOptions";

export function authorizationCode(options: AuthorizationCodeOptions): Implementation[] {
    let opts: AuthorizationCodeOptions = defaultOpts(options, 'authorization-code');
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
                            error_description: 'Missing code challenge',
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
                        error_description: 'Encountered an unexpected database error',
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
                let {client_id, client_secret} = opts.getClientCredentials(req);
                let {code, redirect_uri, code_verifier} = req.body;
                if (client_id.length === 0) client_id = req.body.client_id;

                // Check PKCE parameter
                if (opts.usePKCE && !code_verifier)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Missing code verifier',
                        status: 400,
                    });

                // Token verification
                let authCodePayload: any = verifyToken(code, serverOpts.secret);
                if (!authCodePayload)
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: 'Authorization code is not valid or has expired',
                        status: 400,
                    })

                // Payload verification
                if (authCodePayload.client_id !== client_id)
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: 'Authorization code does not belong to the client',
                        status: 400,
                    });

                // Do database request at last to lessen db costs.
                if (!(await opts.validateClient(client_id, client_secret)))
                    return callback(undefined, {
                        error: 'unauthorized_client',
                        error_description: 'Client authentication failed',
                        status: 400,
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
                        error_description: 'Authorization code is not valid or has expired',
                        status: 400,
                    });

                if (redirect_uri !== dbCode.redirectUri)
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: 'Redirect URI is not the same that was used during authorization code grant',
                        status: 400,
                    });

                // Check PKCE
                if (opts.usePKCE) {
                    if (dbCode.codeChallenge !== codeChallengeHash((dbCode.codeChallengeMethod as any), code_verifier))
                        return callback(undefined, {
                            error: 'invalid_grant',
                            error_description: 'Code verifier is not valid',
                            status: 400,
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
                    accessTokenExpiresAt: tokens.expires_in ? Math.trunc((Date.now() + serverOpts.accessTokenLifetime * 1000) / 1000) : undefined,
                    refreshToken: tokens.refresh_token,
                    refreshTokenExpiresAt: tokens.refresh_token ? Math.trunc((Date.now() + serverOpts.refreshTokenLifetime * 1000) / 1000) : undefined,
                    clientId: client_id,
                    user: dbCode.user,
                    scopes: dbCode.scopes,
                });

                if(!dbRes)
                    return callback(undefined, {
                        error: 'server_error',
                        error_description: 'Encountered an unexpected database error'
                    });

                callback(tokens);
            }
        }
    ]
}