import {ServerOptions} from "../components/serverOptions";
import {GrantTypes} from "../components/GrantTypes";
import * as crypto from "crypto";
import {TokenErrorRequest} from "../components/tokenErrorRequest";
import {AuthorizeErrorRequest} from "../components/authorizeErrorRequest";
import {OAuth2Exception} from "../components/OAuth2Exception";


export async function someAsync(arr: any[], check: (element: any) => Promise<boolean>): Promise<boolean> {
    for (let i = 0; i < arr.length; i++) {
        if (await check(arr[i]))
            return true;
    }
    return false;
}

export async function parseScopes(scope: string | undefined | null, options: Partial<ServerOptions>): Promise<string[] | null> {
    let scopes: string[] = scope?.split(options.scopeDelimiter) || [];
    if (scopes.length === 0) {
        if (!(await options.isScopeValid('')))
            return null;
    } else if (await someAsync(scopes, async s => !(await options.isScopeValid(s))))
        return null;
    return scopes;
}

export function buildRedirectURI(redirectURI: string, params: object): string {
    let r = `${redirectURI}?`;
    for (const key in params)
        r += `${key}=${params[key]}&`;

    return r.substring(0, r.length - 1);
}

export function errorBody(res: any, err: TokenErrorRequest, description: string) {
    let status = 400;
    if (err === TokenErrorRequest.INVALID_CLIENT)
        status = 401;

    description = description.endsWith('.') ? description : `${description}.`;
    res.status(status)
        .header('WWW-Authenticate', `error=${err}`)
        .header('WWW-Authenticate', `error_description=${description}`)
        .json({
            error: err,
            error_description: description,
            error_uri: 'Please check the docs for more information.'
        });
}

export function errorRedirect(res: any, err: AuthorizeErrorRequest, redirectUri: string, state: string, description: string) {
    description = description.endsWith('.') ? description : `${description}.`;
    res.header('WWW-Authenticate', `error=${err}`)
        .header('WWW-Authenticate', `error_description=${description}`)
        .redirect(buildRedirectURI(redirectUri, {
            error: err,
            error_description: description,
            error_uri: 'Please check the docs for more information',
            state
        }));
}

function encodeBase64URL(str: string): string {
    return str.replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

export function codeChallengeHash(challenge: 'plain' | 'S256', str: string): string {
    let code = str;
    if (challenge === 'S256') {
        code = crypto.createHash('sha256').update(code).digest('base64');
        code = encodeBase64URL(code);
    }
    return code;
}

export function getGrantType(str: string): GrantTypes | null {
    switch (str) {
        case 'code':
        case 'authorization_code':
            return GrantTypes.AUTHORIZATION_CODE;
        case 'token':
            return GrantTypes.IMPLICIT;
        case 'password':
            return GrantTypes.RESOURCE_OWNER_CREDENTIALS;
        case 'client_credentials':
            return GrantTypes.CLIENT_CREDENTIALS;
        case 'refresh_token':
            return GrantTypes.REFRESH_TOKEN;
        default:
            return null;
    }
}

export function mergeOptions(global: Partial<ServerOptions>, func: Partial<ServerOptions>): Partial<ServerOptions> {
    return {...global, ...func};
}

export function checkOptions(opts: Partial<ServerOptions>, type: 'authorize' | 'token' | 'authenticate') {
    if (!Array.isArray(opts.grantTypes))
        throw new OAuth2Exception('grantTypes must be an array');

    // Remove duplicate records
    opts.grantTypes = opts.grantTypes.filter((e, i) => opts.grantTypes.indexOf(e) === i);

    if (typeof opts.scopeDelimiter !== 'string')
        throw new OAuth2Exception('scopeDelimiter must be type string');
    if (typeof opts.isScopeValid !== 'function')
        throw new OAuth2Exception('isScopeValid must be a function');
    if (typeof opts.secret !== 'string')
        throw new OAuth2Exception('secret must be type string');

    if (!opts.tokenHandler)
        throw new OAuth2Exception('tokenHandler must be initialized');

    if (type === 'authenticate') {
        if (typeof opts.getToken !== 'function')
            throw new OAuth2Exception('getToken must be a function');
        if (typeof opts.setPayloadLocation !== 'function')
            throw new OAuth2Exception('setPayloadLocation must be a function');

        if (typeof opts.tokenHandler.getAccessToken !== 'function')
            throw new OAuth2Exception('tokenHandler.getAccessToken must be a function');
    }

    if (type === 'authorize') {
        if (typeof opts.allowNonHTTPSRedirectURIs !== 'boolean')
            throw new OAuth2Exception('allowNonHTTPSRedirectURIs must be type boolean');
        if (typeof opts.minStateLength !== 'number')
            throw new OAuth2Exception('minStateLength must be type number');
        if (typeof opts.getUser !== 'function')
            throw new OAuth2Exception('getUser must be a function');
        if (typeof opts.validateRedirectURI !== 'function')
            throw new OAuth2Exception('validateRedirectURI must be a function');

        if (opts.grantTypes.includes(GrantTypes.AUTHORIZATION_CODE)) {
            if (typeof opts.authorizationCodeLifetime !== 'number'
                || Math.trunc(opts.authorizationCodeLifetime) !== opts.authorizationCodeLifetime
                || opts.authorizationCodeLifetime <= 0)
                throw new OAuth2Exception('authorizationCodeLifetime must be a positive integer');

            if (typeof opts.usePKCE !== 'boolean')
                throw new OAuth2Exception('usePKCE must be type boolean');

            if (opts.usePKCE) {
                if (typeof opts.allowCodeChallengeMethodPlain !== 'boolean')
                    throw new OAuth2Exception('allowCodeChallengeMethodPlain must be type boolean');
            }

            if (typeof opts.tokenHandler.saveAuthorizationCode !== 'function')
                throw new OAuth2Exception('tokenHandler.saveAuthorizationCode must be a function');
        }
    }

    if (type === 'token') {
        if (typeof opts.usePKCE !== 'boolean')
            throw new OAuth2Exception('usePKCE must be type boolean');
        if (typeof opts.getClientCredentials !== 'function')
            throw new OAuth2Exception('getClientCredentials must be a function');
        if (typeof opts.validateClient !== 'function')
            throw new OAuth2Exception('validateClient must be a function');

        if (opts.grantTypes.includes(GrantTypes.RESOURCE_OWNER_CREDENTIALS)) {
            if (typeof opts.validateUser !== 'function')
                throw new OAuth2Exception('validateUser must be a function')
        }

        if (opts.grantTypes.includes(GrantTypes.REFRESH_TOKEN)) {
            if (typeof opts.tokenHandler.getRefreshToken !== 'function')
                throw new OAuth2Exception('tokenHandler.getRefreshToken must be a function');
            if (typeof opts.tokenHandler.deleteTokens !== 'function')
                throw new OAuth2Exception('tokenHandler.deleteTokens must be a function');
        }

        if (opts.grantTypes.includes(GrantTypes.AUTHORIZATION_CODE)) {
            if (typeof opts.tokenHandler.getAuthorizationCode !== 'function')
                throw new OAuth2Exception('tokenHandler.getAuthorizationCode must be a function');
            if (typeof opts.tokenHandler.deleteAuthorizationCode !== 'function')
                throw new OAuth2Exception('tokenHandler.deleteAuthorizationCode must be a function');
        }
    }

    if (type === 'token' || (type === 'authorize' && opts.grantTypes.includes(GrantTypes.IMPLICIT))) {
        if (typeof opts.accessTokenLifetime !== 'number'
            || Math.trunc(opts.accessTokenLifetime) !== opts.accessTokenLifetime
            || opts.accessTokenLifetime <= 0)
            throw new OAuth2Exception('accessTokenLifetime must be a positive integer');

        // If the only grantType is CLIENT_CREDENTIALS then do not check for refresh token settings
        if (type !== 'token' || opts.grantTypes.length !== 1 || !opts.grantTypes.includes(GrantTypes.CLIENT_CREDENTIALS)) {
            if (typeof opts.issueRefreshToken !== 'boolean')
                throw new OAuth2Exception('issueRefreshToken must be type boolean');

            if (opts.issueRefreshToken) {
                if (typeof opts.refreshTokenLifetime !== 'number'
                    || Math.trunc(opts.refreshTokenLifetime) !== opts.refreshTokenLifetime
                    || opts.refreshTokenLifetime <= 0)
                    throw new OAuth2Exception('refreshTokenLifetime must be a positive integer');
            }
        }

        if (typeof opts.tokenHandler.saveTokens !== 'function')
            throw new OAuth2Exception('tokenHandler.saveTokens must be a function');
    }
}