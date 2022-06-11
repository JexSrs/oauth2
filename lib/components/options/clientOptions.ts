export type ClientOptions = {
    // For authorization flow
    authorizationURL: string;
    tokenURL: string;
    clientID: string;
    clientSecret: string;
    callbackURL: string;
    usePKCE: boolean;
};