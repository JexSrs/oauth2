import {Implementation} from "../components/implementation";
import {generateARTokens, signToken, verifyToken, getTokenExpiresAt} from "../modules/tokenUtils";
import {DeviceFlowOptions} from "../components/options/implementations/deviceFlowOptions";
import {randStr} from "../modules/utils";
import {Events} from "../components/events";

export function deviceFlow(options: DeviceFlowOptions): Implementation[] {
    let opts = {...options};

    if(opts.interval === undefined)
        opts.interval = 5;
    else if (opts.interval <= 0
        || Math.trunc(opts.interval) !== opts.interval)
        throw new Error('interval is not positive integer.');

    if(opts.expiresIn === undefined)
        opts.expiresIn = 5;
    else if (opts.expiresIn <= 0
        || Math.trunc(opts.expiresIn) !== opts.expiresIn)
        throw new Error('expiresIn is not positive integer.');

    if(opts.removeOnExpired === undefined)
        opts.removeOnExpired = true;

    if(opts.removeOnDenied === undefined)
        opts.removeOnDenied = true;

    if(opts.deviceCodeGenerator === undefined)
        opts.deviceCodeGenerator = (client_id) => randStr(64);
    else if(typeof  opts.deviceCodeGenerator !== 'function')
        throw new Error('deviceCodeGenerator must be a function');

    if(opts.userCodeGenerator === undefined)
        opts.userCodeGenerator = (client_id) => `${randStr(4)}-${randStr(4)}`;
    else if(typeof  opts.userCodeGenerator !== 'function')
        throw new Error('userCodeGenerator must be a function');

    if(opts.verificationURI.trim().length === 0)
        throw new Error('verificationURI must be non empty string');

    return [
        {
            name: 'device-flow',
            endpoint: 'device',
            matchType: 'token',
            function: async (req, serverOpts, issueRefreshToken, callback, eventEmitter) => {
                const {client_id, scope} = req.body;

                if(!client_id)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Property client_id is missing'
                    });

                let scopes = scope?.split(serverOpts.scopeDelimiter) || [];
                if (!(await serverOpts.isScopesValid(scopes))) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_DEVICE_CODE_SCOPES_INVALID, req);
                    return callback(undefined, {
                        error: 'invalid_scope',
                        error_description: 'One or more scopes are not acceptable'
                    });
                }

                if(!(await opts.validateClient(client_id))) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_DEVICE_CODE_CLIENT_INVALID, req);
                    return callback(undefined, {
                        error: 'unauthorized_client',
                        error_description: 'Client authentication failed'
                    });
                }

                let deviceCode = await opts.deviceCodeGenerator!(client_id);
                let userCode = await opts.userCodeGenerator!(client_id);

                let dbRes = await opts.saveDevice({
                    clientId: client_id,
                    deviceCode,
                    userCode,
                    interval: opts.interval!,
                    expiresAt: Math.trunc((Date.now() + opts.expiresIn! * 1000) / 1000),
                    scopes,
                    status: 'pending'
                });

                if(!dbRes) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_DEVICE_CODE_SAVE_ERROR, req);
                    return callback(undefined, {
                        error: 'server_error',
                        error_description: 'Encountered an unexpected error'
                    });
                }

                callback({
                    device_code: deviceCode,
                    user_code: userCode,
                    verification_uri: opts.verificationURI,
                    interval: opts.interval,
                    expires_in: opts.expiresIn
                });
            }
        },
        {
            name: 'device-flow',
            endpoint: 'token',
            matchType: 'urn:ietf:params:oauth:grant-type:device_code',
            function: async (req, serverOpts, issueRefreshToken, callback, eventEmitter) => {
                let {client_id, device_code} = req.body;

                if(!client_id)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Property client_id is missing'
                    });

                if(!device_code)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Property device_code is missing'
                    });


                // Rate limit using deviceCode
                // We are using jwt tokens to make sure that the bucket is expired,
                // in case the app sends the code even if it has expired.
                const oldBucket = await opts.getBucket(device_code);
                if(oldBucket != null) {
                    const payload = verifyToken(oldBucket, serverOpts.secret);
                    if(payload !== null) {
                        eventEmitter.emit(Events.DEVICE_FLOWS_TOKEN_SLOW_DOWN, req);
                        return callback(undefined, {error: 'slow_down', status: 400});
                    }
                }

                // The signed JWT is internal and will never go to any user or client
                const bucket = signToken({deviceCode: device_code}, serverOpts.secret, opts.interval);
                await opts.saveBucket(device_code, bucket, opts.interval!);

                // Get saved device
                let dbDev = await opts.getDevice({
                    deviceCode: device_code,
                    clientId: client_id
                });

                if(!dbDev || (dbDev.status !== 'pending' && dbDev.status !== 'completed')) {
                    eventEmitter.emit(Events.DEVICE_FLOWS_TOKEN_DEVICE_CODE_INVALID, req);
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: 'Device code not found',
                        status: 400
                    });
                }

                if(dbDev.expiresAt > Math.trunc(Date.now() / 1000)) {
                    if(opts.removeOnExpired)
                        await opts.removeDevice({
                            clientId: client_id,
                            deviceCode: device_code
                        });

                    eventEmitter.emit(Events.DEVICE_FLOWS_TOKEN_EXPIRED, req);
                    return callback(undefined, {error: 'expired_token', status: 400});
                }

                if(dbDev.status === 'pending') {
                    eventEmitter.emit(Events.DEVICE_FLOWS_TOKEN_PENDING, req);
                    return callback(undefined, {error: 'authorization_pending', status: 400});
                }

                // Request completed - Get user if authorized
                let user = await opts.getUser(dbDev.deviceCode, dbDev.userCode);
                if (!user) {
                    if(opts.removeOnDenied)
                        await opts.removeDevice({
                            clientId: client_id,
                            deviceCode: device_code
                        });
                    eventEmitter.emit(Events.DEVICE_FLOWS_TOKEN_ACCESS_DENIED, req);
                    return callback(undefined, {error: 'access_denied', status: 400});
                }

                await opts.removeDevice({
                    clientId: client_id,
                    deviceCode: device_code
                });

                // Generate access & refresh tokens
                let tokens = await generateARTokens({user}, client_id, dbDev.scopes, serverOpts, issueRefreshToken);

                // Database save
                let dbRes = await serverOpts.saveTokens({
                    accessToken: tokens.access_token,
                    accessTokenExpiresAt: getTokenExpiresAt(tokens, serverOpts.accessTokenLifetime!, 'access'),
                    refreshToken: tokens.refresh_token,
                    refreshTokenExpiresAt: getTokenExpiresAt(tokens, serverOpts.refreshTokenLifetime!, 'refresh'),
                    clientId: client_id,
                    user,
                    scopes: dbDev.scopes,
                });

                if(!dbRes) {
                    eventEmitter.emit(Events.DEVICE_FLOWS_TOKEN_SAVE_ERROR, req);
                    return callback(undefined, {
                        error: 'server_error',
                        error_description: 'Encountered an unexpected error'
                    });
                }

                callback(tokens);
            }
        }
    ];
}