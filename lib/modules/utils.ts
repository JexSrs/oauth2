import * as jwt from "jsonwebtoken";
import {ServerOptions} from "../components/serverOptions";
import {ARTokensResponse, ClientCredentials} from "../components/types";

export function signToken(payload: object, secret: string, expiresIn?: number): string {
    return jwt.sign(payload, secret, {
        algorithm: 'HS512',
        expiresIn
    });
}

export function verifyToken(token: string, secret: string): object {
    return jwt.verify(token, secret) as any;
}

export async function someAsync(arr: any[], check: (element: any) => Promise<boolean>): Promise<boolean> {
    for (let i = 0; i < arr.length; i++){
        if(await check(arr[i]))
            return true;
    }
    return false;
}

export async function generateARTokens(client_id: string, scopes: string[], req: any, options: ServerOptions): Promise<ARTokensResponse> {
    let accessTokenPayload = {
        ...options.includeToPayload(req),
        client_id,
        scopes,
        type: 'accessToken'
    };
    let refreshTokenPayload = {
        client_id,
        scopes,
        type: 'refreshToken'
    };

    let accessToken: string = options.tokenUtils.sign(accessTokenPayload, options.accessTokenLifetime);
    let refreshToken: string | undefined;
    if(this.options.allowRefreshToken)
        refreshToken = options.tokenUtils.sign(refreshTokenPayload, options.refreshTokenLifetime);

    // Database save
    await options.database.saveToken({
        accessToken,
        payload: accessTokenPayload,
        accessTokenExpiresAt: Math.trunc((Date.now() + options.accessTokenLifetime * 1000) / 1000),
        refreshToken,
        refreshTokenExpiresAt: Math.trunc((Date.now() + options.refreshTokenLifetime * 1000) / 1000),
    });

    return {
        access_token: accessToken,
        token_type: 'bearer',
        expires_in: options.accessTokenLifetime,
        refresh_token: refreshToken,
        refresh_token_expires_in: refreshToken ? options.refreshTokenLifetime : undefined,
    };
}

export function getCredentials(req: any): ClientCredentials {
    let authHeader = req.headers['authorization'];
    let decoded = authHeader
        && Buffer.from(authHeader, 'base64').toString()
        || '';

    let [client_id, client_secret] = /^([^:]*):(.*)$/.exec(decoded);
    return {
        client_id: client_id || '',
        client_secret: client_secret || ''
    };
}

export async function parseScopes(scope: string, options: ServerOptions): Promise<string[] | null> {
    let scopes: string[] = scope.split(options.scopeDelimiter);
    if ((Array.isArray(options.acceptedScopes)
            && scopes.some(s => !(options.acceptedScopes as string[]).includes(s)))
        || await someAsync(scopes, async s => !(await (options.acceptedScopes as any)(s)))
    ) return null;
    return scopes;
}