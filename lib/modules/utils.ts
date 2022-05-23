import {AuthorizationServerOptions} from "../components/options/authorizationServerOptions";
import {GrantType} from "../components/GrantType";
import * as crypto from "crypto";
import {TokenErrorRequest} from "../components/errors/tokenErrorRequest";
import {AuthorizeErrorRequest} from "../components/errors/authorizeErrorRequest";
import {OAuth2Exception} from "../components/exceptions/OAuth2Exception";
import {AuthenticateErrorRequest} from "../components/errors/authenticateErrorRequest";

export async function parseScopes(scope: string | undefined | null, options: Partial<AuthorizationServerOptions>): Promise<string[] | null> {
    let scopes: string[] = scope?.split(options.scopeDelimiter) || [];
    if (!(await options.isScopesValid(scopes)))
        return null;
    return scopes;
}

export function buildRedirectURI(redirectURI: string, params: object): string {
    let r = `${redirectURI}?`;
    for (const key in params)
        r += `${key}=${params[key]}&`;

    return r.substring(0, r.length - 1);
}

export function tokenError(res: any, err: TokenErrorRequest, description: string): void {
    let status = 400;
    if (err === TokenErrorRequest.INVALID_CLIENT)
        status = 401;

    description = description.endsWith('.') ? description : `${description}.`;
    res.status(status)
        .header('WWW-Authenticate', `Bearer error=${err} error_description=${description}`)
        .json({
            error: err,
            error_description: description,
            error_uri: 'Please check the docs for more information.'
        });
}

export function authenticateError(res: any, err: AuthenticateErrorRequest, description: string): void {
    let status = 0;
    switch (err) {
        case AuthenticateErrorRequest.INVALID_REQUEST:
            status = 400;
            break;
        case AuthenticateErrorRequest.INVALID_TOKEN:
            status = 401;
            break;
        case AuthenticateErrorRequest.INSUFFICIENT_SCOPE:
            status = 403;
            break;
    }

    description = description.endsWith('.') ? description : `${description}.`;
    res.status(status)
        .header('WWW-Authenticate', `Bearer error=${err} error_description=${description}`)
        .json({
            error: err,
            error_description: description,
            error_uri: 'Please check the docs for more information.'
        });
}

export function authorizeError(res: any, err: AuthorizeErrorRequest, redirectUri: string, state: string, description: string): void {
    description = description.endsWith('.') ? description : `${description}.`;
    res.header('WWW-Authenticate', `Bearer error=${err} error_description=${description}`)
        .redirect(buildRedirectURI(redirectUri, {
            error: err,
            error_description: description,
            error_uri: 'Please check the docs for more information',
            state
        }));
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

export function getGrantType(str: string): GrantType | null {
    switch (str) {
        case 'code':
        case 'authorization_code':
            return GrantType.AUTHORIZATION_CODE;
        case 'token':
            return GrantType.IMPLICIT;
        case 'password':
            return GrantType.RESOURCE_OWNER_CREDENTIALS;
        case 'client_credentials':
            return GrantType.CLIENT_CREDENTIALS;
        case 'refresh_token':
            return GrantType.REFRESH_TOKEN;
        default:
            return null;
    }
}

export function isEmbeddedWebView(req: any): boolean {
    // TODO - embedded web view
    return false;
}

export function mergeOptions(global?: Partial<AuthorizationServerOptions>, func?: Partial<AuthorizationServerOptions>): Partial<AuthorizationServerOptions> {
    if (!func) return global;
    if (!global) return func;
    return {...global, ...func};
}

export function checkOptions(opts: Partial<AuthorizationServerOptions>, type: 'authorize' | 'token' | 'authenticate' | 'introspection') {
    if (!Array.isArray(opts.grantTypes))
        throw new OAuth2Exception('grantTypes must be an array');

    // Remove duplicate records
    opts.grantTypes = opts.grantTypes.filter((e, i) => opts.grantTypes.indexOf(e) === i);

    if (typeof opts.scopeDelimiter !== 'string')
        throw new OAuth2Exception('scopeDelimiter must be type string');
    if (typeof opts.isScopesValid !== 'function')
        throw new OAuth2Exception('isScopesValid must be a function');
    if (typeof opts.secret !== 'string')
        throw new OAuth2Exception('secret must be type string');
    if (typeof opts.issuer !== 'undefined' && typeof opts.issuer !== 'string')
        throw new OAuth2Exception('issuer must be type string');

    if (!opts.tokenHandler)
        throw new OAuth2Exception('tokenHandler must be initialized');

    if (type === 'introspection') {
        if (typeof opts.tokenHandler.getAccessToken !== 'function')
            throw new OAuth2Exception('tokenHandler.getAccessToken must be a function');
    }

    if (type === 'authenticate') {
        if (typeof opts.getToken !== 'function')
            throw new OAuth2Exception('getToken must be a function');
        if (typeof opts.setPayloadLocation !== 'function')
            throw new OAuth2Exception('setPayloadLocation must be a function');

        if (typeof opts.tokenHandler.getAccessToken !== 'function')
            throw new OAuth2Exception('tokenHandler.getAccessToken must be a function');
    }

    if (type === 'authorize') {
        if (typeof opts.getUser !== 'function')
            throw new OAuth2Exception('getUser must be a function');
        if (typeof opts.validateRedirectURI !== 'function')
            throw new OAuth2Exception('validateRedirectURI must be a function');
        if (typeof opts.rejectEmbeddedWebViews !== 'boolean')
            throw new OAuth2Exception('rejectEmbeddedWebViews must be type boolean');

        if (opts.grantTypes.includes(GrantType.AUTHORIZATION_CODE)) {
            if (typeof opts.authorizationCodeLifetime !== 'number'
                || Math.trunc(opts.authorizationCodeLifetime) !== opts.authorizationCodeLifetime
                || opts.authorizationCodeLifetime <= 0)
                throw new OAuth2Exception('authorizationCodeLifetime must be a positive integer');

            if (typeof opts.usePKCE !== 'boolean') throw new OAuth2Exception('usePKCE must be type boolean');

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

        if (opts.grantTypes.includes(GrantType.RESOURCE_OWNER_CREDENTIALS)) {
            if (typeof opts.validateUser !== 'function')
                throw new OAuth2Exception('validateUser must be a function')
        }

        if (opts.grantTypes.includes(GrantType.REFRESH_TOKEN)) {
            if (typeof opts.tokenHandler.getRefreshToken !== 'function')
                throw new OAuth2Exception('tokenHandler.getRefreshToken must be a function');
            if (typeof opts.tokenHandler.deleteTokens !== 'function')
                throw new OAuth2Exception('tokenHandler.deleteTokens must be a function');
        }

        if (opts.grantTypes.includes(GrantType.AUTHORIZATION_CODE)) {
            if (typeof opts.tokenHandler.getAuthorizationCode !== 'function')
                throw new OAuth2Exception('tokenHandler.getAuthorizationCode must be a function');
            if (typeof opts.tokenHandler.deleteAuthorizationCode !== 'function')
                throw new OAuth2Exception('tokenHandler.deleteAuthorizationCode must be a function');
        }
    }

    if (type === 'token' || (type === 'authorize' && opts.grantTypes.includes(GrantType.IMPLICIT))) {
        if (opts.accessTokenLifetime != null && (typeof opts.accessTokenLifetime !== 'number'
            || Math.trunc(opts.accessTokenLifetime) !== opts.accessTokenLifetime
            || opts.accessTokenLifetime <= 0))
            throw new OAuth2Exception('accessTokenLifetime must be a positive integer');

        // If type is token and the only grantType is CLIENT_CREDENTIALS then check for refresh token settings
        if (type === 'token' && (opts.grantTypes.length !== 1 || !opts.grantTypes.includes(GrantType.CLIENT_CREDENTIALS))) {
            if (opts.grantTypes.includes(GrantType.REFRESH_TOKEN)) {
                if (opts.refreshTokenLifetime != null && (typeof opts.refreshTokenLifetime !== 'number'
                    || Math.trunc(opts.refreshTokenLifetime) !== opts.refreshTokenLifetime
                    || opts.refreshTokenLifetime <= 0))
                    throw new OAuth2Exception('refreshTokenLifetime must be a positive integer');
            }
        }

        if (typeof opts.tokenHandler.saveTokens !== 'function')
            throw new OAuth2Exception('tokenHandler.saveTokens must be a function');
    }

    if(type === 'authorize' || type === 'token') {
        if(typeof opts.isGrantTypeAllowed !== 'function')
            throw new OAuth2Exception('isGrantTypeAllowed must be a function');
    }
}