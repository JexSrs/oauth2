import * as crypto from "crypto";

export function buildRedirectURI(redirectURI: string, params: object): string {
    let r = `${redirectURI}?`;
    for (const key in params)
        r += `${key}=${params[key]}&`;

    return r.substring(0, r.length - 1);
}

export function codeChallengeHash(challenge: 'plain' | 'S256', str: string): string {
    let code = str;
    if (challenge === 'S256') {
        // Hash
        code = crypto.createHash('sha256').update(code).digest('base64');

        // Encode base64 url
        code = code.replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }
    return code;
}

export function isEmbeddedWebView(req: any): boolean {
    // TODO - embedded web view
    return false;
}

export function defaultOpts(options: any, type: 'authorization-code' | 'client-credentials' | 'refresh-token' | 'resource-owner-credentials') {
    let opts = options || {};

    if(type === 'client-credentials'
        || type === 'authorization-code'
        || type === 'refresh-token'
        || type === 'resource-owner-credentials'
    ) {
        if(typeof opts.getClientCredentials !== 'function') {
            opts.getClientCredentials = (req: any) => {
                let authHeader = req.headers['authorization'];
                let decoded = authHeader && Buffer.from(authHeader, 'base64').toString() || '';

                let [client_id, client_secret] = /^([^:]*):(.*)$/.exec(decoded);
                return {client_id, client_secret};
            };
        }

        if(typeof opts.validateClient !== 'function')
            throw new Error('validateClient is not a function');
    }

    if(type === 'authorization-code') {
        if(typeof opts.usePKCE !== 'boolean')
            opts.usePKCE = true;
        if(typeof opts.allowCodeChallengeMethodPlain !== 'boolean')
            opts.allowCodeChallengeMethodPlain = false;

        if (typeof opts.authorizationCodeLifetime !== 'number')
            opts.authorizationCodeLifetime = 60;
        else if (opts.authorizationCodeLifetime <= 0 || Math.trunc(opts.authorizationCodeLifetime) !== opts.authorizationCodeLifetime)
            throw new Error('authorizationCodeLifetime is not positive integer.');

        if(typeof opts.saveAuthorizationCode !== 'function')
            throw new Error('saveAuthorizationCode is not a function');

        if(typeof opts.getAuthorizationCode !== 'function')
            throw new Error('getAuthorizationCode is not a function');

        if(typeof opts.deleteAuthorizationCode !== 'function')
            throw new Error('deleteAuthorizationCode is not a function');
    }

    if(type === 'refresh-token') {
        if(typeof opts.getRefreshToken !== 'function')
            throw new Error('getRefreshToken is not a function');
        if(typeof opts.deleteTokens !== 'function')
            throw new Error('deleteTokens is not a function');
    }

    if(type === 'resource-owner-credentials') {
        if(typeof opts.validateUser !== 'function')
            throw new Error('validateUser is not a function');
    }

    return opts;
}
