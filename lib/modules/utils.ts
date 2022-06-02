import * as crypto from "crypto";

export function buildRedirectURI(redirectURI: string, params: { [key: string]: string | undefined }): string {
    let r = `${redirectURI}?`;
    for (const key in params) {
        if(params[key] !== undefined)
            r += `${key}=${params[key]}&`;
    }

    return r.substring(0, r.length - 1);
}

export function codeChallengeHash(challenge: 'plain' | 'S256' | undefined, str: string): string {
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
    //      - https://stackoverflow.com/questions/37591279/detect-if-user-is-using-webview-for-android-ios-or-a-regular-browser
    return false;
}

export function defaultCommonOpts(options: any) {
    let opts = options || {};

    if(typeof opts.validateClient !== 'function')
        throw new Error('validateClient is not a function');

    return opts;
}

export function randStr(length: number): string {
    const chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890";
    const randomArray = Array.from({ length: length },
        (v, k) => chars[Math.floor(Math.random() * chars.length)]
    );
    return randomArray.join("");
}
