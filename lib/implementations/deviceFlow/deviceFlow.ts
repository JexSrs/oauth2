import {Implementation} from "../../components/implementation";
import {generateARTokens, getTokenExpiresAt, signToken, verifyToken} from "../../modules/tokenUtils";
import {DeviceFlowOptions} from "./deviceFlowOptions";
import {randStr} from "../../modules/utils";
import {Events} from "../../components/events";

export function deviceFlow(options: DeviceFlowOptions): Implementation[] {
    let opts = {...options};

    if (opts.interval === undefined)
        opts.interval = 5;
    else if (opts.interval <= 0
        || Math.trunc(opts.interval) !== opts.interval)
        throw new Error('interval is not positive integer.');

    if (opts.expiresIn === undefined)
        opts.expiresIn = 5;
    else if (opts.expiresIn <= 0
        || Math.trunc(opts.expiresIn) !== opts.expiresIn)
        throw new Error('expiresIn is not positive integer.');

    if (opts.deviceCodeGenerator === undefined)
        opts.deviceCodeGenerator = (client_id) => randStr(64);
    else if (typeof opts.deviceCodeGenerator !== 'function')
        throw new Error('deviceCodeGenerator must be a function');

    if (opts.userCodeGenerator === undefined)
        opts.userCodeGenerator = (client_id) => `${randStr(4)}-${randStr(4)}`;
    else if (typeof opts.userCodeGenerator !== 'function')
        throw new Error('userCodeGenerator must be a function');

    if (opts.verificationURI.trim().length === 0)
        throw new Error('verificationURI must be non empty string');

    return [
        {
            name: 'device-flow',
            endpoint: 'device',
            matchType: 'token',
            function: async (data, callback, eventEmitter) => {
                const {client_id} = data.req.body;

                if (!client_id)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Body parameter client_id is missing'
                    });

                if (!(await opts.validateClient(client_id, data.req))) {
                    eventEmitter.emit(Events.DEVICE_FLOWS_TOKEN_CLIENT_INVALID, data.req);
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
                    scopes: data.scopes!,
                    status: 'pending'
                }, data.req);

                if (!dbRes) {
                    eventEmitter.emit(Events.DEVICE_FLOWS_TOKEN_SAVE_ERROR, data.req);
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
            function: async (data, callback, eventEmitter) => {
                let {client_id, device_code} = data.req.body;

                if (!client_id)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Body parameter client_id is missing'
                    });

                if (!device_code)
                    return callback(undefined, {
                        error: 'invalid_request',
                        error_description: 'Body parameter device_code is missing'
                    });

                // Rate limit using deviceCode
                // We are using jwt tokens to make sure that the bucket is expired,
                // in case the app sends the code even if it has expired.
                const oldBucket = await opts.getBucket(device_code, data.req);
                if (oldBucket != null) {
                    const payload = verifyToken(oldBucket, data.serverOpts.secret);
                    if (payload != null) {
                        eventEmitter.emit(Events.TOKEN_FLOWS_DEVICE_CODE_SLOW_DOWN, data.req);
                        return callback(undefined, {error: 'slow_down', status: 400, error_uri: undefined});
                    }
                }

                // The signed JWT is internal and will never go to any user or client
                const bucket = signToken({deviceCode: device_code}, data.serverOpts.secret, opts.interval);
                await opts.saveBucket(device_code, bucket, opts.interval!, data.req);

                // Get saved device
                let dbDev = await opts.getDevice({
                    deviceCode: device_code,
                    clientId: client_id
                }, data.req);

                if (!dbDev || (dbDev.status !== 'pending' && dbDev.status !== 'completed')) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_DEVICE_CODE_DEVICE_CODE_INVALID, data.req);
                    return callback(undefined, {
                        error: 'invalid_grant',
                        error_description: 'Device code not found',
                        status: 400
                    });
                }

                if (dbDev.expiresAt <= Math.trunc(Date.now() / 1000)) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_DEVICE_CODE_EXPIRED, data.req);
                    return callback(undefined, {error: 'expired_token', status: 400});
                }

                if (dbDev.status === 'pending') {
                    eventEmitter.emit(Events.TOKEN_FLOWS_DEVICE_CODE_PENDING, data.req);
                    return callback(undefined, {error: 'authorization_pending', status: 400, error_uri: undefined});
                }

                // Request completed - Get user if authorized
                let user = await opts.getUser(dbDev.deviceCode, dbDev.userCode, data.req);
                if (!user) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_DEVICE_CODE_ACCESS_DENIED, data.req);
                    return callback(undefined, {error: 'access_denied', status: 400});
                }

                await opts.removeDevice({
                    clientId: client_id,
                    deviceCode: device_code
                }, data.req);

                // Generate access & refresh tokens
                let tokens = generateARTokens({user}, client_id, dbDev.scopes, data.serverOpts, data.issueRefreshToken);

                // Database save
                let dbRes = await data.serverOpts.saveTokens({
                    accessToken: tokens.access_token,
                    accessTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.accessTokenLifetime!, 'access'),
                    refreshToken: tokens.refresh_token,
                    refreshTokenExpiresAt: getTokenExpiresAt(tokens, data.serverOpts.refreshTokenLifetime!, 'refresh'),
                    clientId: client_id,
                    user,
                    scopes: dbDev.scopes,
                }, data.req);

                if (!dbRes) {
                    eventEmitter.emit(Events.TOKEN_FLOWS_DEVICE_CODE_SAVE_ERROR, data.req);
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