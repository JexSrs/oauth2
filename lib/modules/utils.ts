import * as jwt from "jsonwebtoken";
import {ServerOptions} from "../components/serverOptions";
import {ARTokensResponse} from "../components/types";
import {GrantTypes} from "../components/GrantTypes";
import * as crypto from "crypto";
import {TokenErrorRequest} from "../components/tokenErrorRequest";
import {AuthorizeErrorRequest} from "../components/authorizeErrorRequest";

export function signToken(payload: object, secret: string, expiresIn?: number): string {
    return jwt.sign(payload, secret, {
        algorithm: 'HS512',
        expiresIn
    });
}

export function verifyToken(token: string, secret: string): object | null {
    try {
        return jwt.verify(token, secret) as any;
    } catch (e) {
        return null;
    }
}

export async function someAsync(arr: any[], check: (element: any) => Promise<boolean>): Promise<boolean> {
    for (let i = 0; i < arr.length; i++) {
        if (await check(arr[i]))
            return true;
    }
    return false;
}

export async function generateARTokens(payload: object, scopes: string[], req: any, options: ServerOptions): Promise<ARTokensResponse> {
    let accessTokenPayload = {
        ...payload,
        scopes,
        type: 'accessToken'
    };
    let refreshTokenPayload = {
        ...payload,
        scopes,
        type: 'refreshToken'
    };

    let accessToken: string = signToken(accessTokenPayload, options.secret, options.accessTokenLifetime ?? undefined);
    let refreshToken: string | undefined;
    if (this.options.allowRefreshToken)
        refreshToken = signToken(refreshTokenPayload, options.secret, options.refreshTokenLifetime ?? undefined);

    // Database save
    await options.tokenHandler.saveTokens({
        accessToken,
        accessTokenExpiresAt: Math.trunc((Date.now() + options.accessTokenLifetime * 1000) / 1000),
        refreshToken,
        refreshTokenExpiresAt: Math.trunc((Date.now() + options.refreshTokenLifetime * 1000) / 1000),
        clientId: (payload as any).client_id,
        user: (payload as any).user,
    });

    return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: options.accessTokenLifetime,
        refresh_token: refreshToken,
    };
}

export async function parseScopes(scope: string | undefined | null, grantType: GrantTypes, options: ServerOptions): Promise<string[] | null> {
    let scopes: string[] = scope?.split(options.scopeDelimiter) || [];
    if (scopes.length === 0) {
        if (!(await options.isScopeValid('', grantType)))
            return null;
    } else if (await someAsync(scopes, async s => !(await options.isScopeValid(s, grantType))))
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

export function hash(challenge: 'plain' | 'S256', str: string): string {
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