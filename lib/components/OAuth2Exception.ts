export class OAuth2Exception extends Error {
    constructor(message?: string) {
        message = `OAuth2Exception ${message}`;
        super(message);
        Object.setPrototypeOf(this, OAuth2Exception.prototype);
    }
}