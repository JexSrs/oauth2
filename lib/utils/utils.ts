import * as crypto from "crypto";
import {OAuth2Error} from "../components/types";

/**
 * Will create a query string from an object.
 * @param params
 */
export function buildQuery(params: { [key: string]: string | undefined }): string {
    return Object.keys(params).map(k => params[k] ? `${k}=${params[k]}` : undefined).filter(s => s != undefined).join('&');
}

/**
 * Will generate the code_challenge from the code verifier and code challenge method.
 * @param method The code challenge method.
 * @param verifier The code verifier.
 */
export function codeChallengeHash(method: 'plain' | 'S256' | undefined, verifier: string): string {
    let code = verifier;
    if (method === 'S256') {
        // Hash
        code = crypto.createHash('sha256').update(code).digest('base64');

        // Encode base64 url
        code = code.replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }
    return code;
}

/**
 * Will generate a random string.
 * @param length The length of the string.
 */
export function randStr(length: number): string {
    const chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890";
    const randomArray = Array.from({ length: length },
        (v, k) => chars[Math.floor(Math.random() * chars.length)]
    );
    return randomArray.join("");
}

export function userCodeGenerator(): string {
    const chars = "BCDFGHJKLMNPQRSTVWXZ";
    const randomArray = Array.from({ length: 8 },
        (v, k) => chars[Math.floor(Math.random() * chars.length)]
    );

    const code = randomArray.join("");
    return `${code.substring(0, 4)}-${code.substring(4, 8)}`;
}

/**
 * Will build and send the error response.
 * If a redirect uri is provided, the response will be redirected.
 * @param res
 * @param data
 */
export function error(res: any, data: OAuth2Error & { redirect_uri?: string; state?: string; status?: number; noCache?: boolean }) {
    // Assign WWW-Authenticate header
    let wwwAuthHeader = `Bearer error="${data.error}"`;
    if (data.error_description) wwwAuthHeader += ` error_description="${data.error_description}"`;
    if (data.error_uri) wwwAuthHeader += ` error_uri="${data.error_uri}"`;

    res.header('WWW-Authenticate', wwwAuthHeader)

    // Set no cache
    if(data.noCache == undefined || data.noCache)
        res.header('Cache-Control', 'no-store')

    let resp: any = {
        error: data.error,
        error_description: data.error_description,
        error_uri: data.error_uri,
    };

    if(data.state != undefined)
        resp.state = data.state;

    if (data.redirect_uri)
        res.redirect(`${data.redirect_uri}?${buildQuery(resp)}`);
    else
        res.status(data.status || 400).json(resp)
}

export function isLocalhost(uri: string): boolean {
    const regex = /http:\/\/(localhost|127\.0\.0\.1|::1):\d{1,5}(\/.*)?/;
    return uri.match(regex)?.[0] === uri;
}

export function isRedirectUriExactMatch(original: string, fromClient: any): boolean {
    // If original is not `localhost` return exact match
    if(!isLocalhost(original))
        return original === fromClient;

    // Check if both urls are localhost
    return typeof fromClient === 'string' && isLocalhost(fromClient);
}

export function resolveUrl(baseUrl: string, endpoint: string): string {
    if((baseUrl.endsWith('/') && !endpoint.startsWith('/'))
        || (!baseUrl.endsWith('/') && endpoint.startsWith('/')))
        return baseUrl + endpoint;

    if(baseUrl.endsWith('/') && endpoint.startsWith('/'))
        return `${baseUrl}${endpoint.substring(1)}`;

    return `${baseUrl}/${endpoint}`;
}

export async function passToNext<T, E>(processes: E[], first: T, call: (proc: E, value: T) => Promise<T>): Promise<T> {
    let response = first;
    for (const proc of processes)
        response = await call(proc, response);
    return response;
}