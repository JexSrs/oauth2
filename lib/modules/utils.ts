import * as jwt from "jsonwebtoken";
import {ServerOptions} from "../components/serverOptions";
import {ARTokensResponse, GrantType} from "../components/types";

export async function allowedMethod(req: any, res: any, method: string, cb: any) {
    if(req.method === method)
        await cb(req, res);
    else res.status(405).end('Method not allowed.');
}

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

export async function parseScopes(scope: string, grantType: GrantType, options: ServerOptions): Promise<string[] | null> {
    let scopes: string[] = scope.split(options.scopeDelimiter);
    if (await someAsync(scopes, async s => !(await options.isScopeValid(s, grantType))))
        return null;
    return scopes;
}

export function objToParams(obj: object): string {
    let r = '?';
    for(const key in obj)
        r += `${key}=${obj[key]}&`;

    return r.substring(0, r.length - 1);
}