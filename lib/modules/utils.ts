import * as jwt from "jsonwebtoken";
import {ServerOptions} from "../components/serverOptions";
import {ARTokensResponse, ErrorRequest, RedirectErrorRequest} from "../components/types";
import {GrantTypes} from "../components/GrantTypes";

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
    for (let i = 0; i < arr.length; i++){
        if(await check(arr[i]))
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
    if(this.options.allowRefreshToken)
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
        refresh_token_expires_in: refreshToken ? options.refreshTokenLifetime : undefined,
    };
}

export async function parseScopes(scope: string | undefined | null, grantType: GrantTypes, options: ServerOptions): Promise<string[] | null> {
    let scopes: string[] = scope?.split(options.scopeDelimiter) || [];
    if(scopes.length === 0) {
        if(!(await options.isScopeValid('', grantType)))
            return null;
    } else if (await someAsync(scopes, async s => !(await options.isScopeValid(s, grantType))))
        return null;
    return scopes;
}

export function buildRedirectURI(redirectURI: string, params: object): string {
    let r = `${redirectURI}?`;
    for(const key in params)
        r += `${key}=${params[key]}&`;

    return r.substring(0, r.length - 1);
}

export function errorBody(res: any, err: ErrorRequest, description: string) {
    let status = 400;
    if(err === 'invalid_client')
        status = 401;

    res.status(status).json({
        error: err,
        error_description: description.endsWith('.') ? description : `${description}.`,
        error_uri: 'Please check the docs for more information.'
    });
}

export function errorRedirect(res: any, err: RedirectErrorRequest, redirectUri: string, state: string, description: string) {
    description = description.endsWith('.') ? description : `${description}.`;
    res.redirect(buildRedirectURI(redirectUri, {
        error: err,
        error_description: description,
        error_uri: 'Please check the docs for more information',
        state
    }));
}

export function encodeBase64URL(str: string): string {
    return str.replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}
