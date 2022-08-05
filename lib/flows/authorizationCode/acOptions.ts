import {THAuthorizationCodeAsk, THAuthorizationCodeSave} from "../../components/types";

export type AuthorizationCodeOptions = {
    /**
     * PKCE (Proof Key for Code Exchange) is an extension to the authorization code flow
     * that enhances protection. More specifically ts to prevents CSRF and authorization code injection attacks.
     * It defaults to `true`.
     *
     * If PKCE is enabled the fields `code_challenge` and `code_challenge_method` must be included in the request.
     */
    usePKCE?: boolean;
    /**
     * The code challenge methods the client is allowed to use.
     * it defaults to `['S256']`.
     *
     * Note this options takes effect only if PKCE is enabled.
     */
    validCodeChallengeMethods?: string[];
    /**
     * This function will take the code verifier and hash it using the code challenge method.
     * It defaults to hashing for the methods `S256` and `plain`.
     *
     * Note this options takes effect only if PKCE is enabled.
     *
     * This function also supports async calls.
     * @param code The code verifier.
     * @param method The code challenge method.
     */
    hashCodeChallenge?: ((code: string, method: string, req: any) => string)
        | ((code: string, method: string, req: any) => Promise<string>);
    /**
     * The time in seconds where the authorization code will be valid. It defaults to `60 sec` = 1 minute.
     */
    authorizationCodeLifetime?: number;
    /**
     * It will override the `errorUri` set at the `AuthorizationServer` options.
     */
    errorUri?: string;
    /**
     * Used by the first stage to save the generated authorization code to the database.
     * It should always return `true` unless the database did not save the record,
     * in that case you must return `false`.
     *
     * This function also supports async calls.
     * @param data The data that needs to be saved.
     * @param req The request instance.
     * @return {boolean} True on success, false otherwise.
     */
    saveAuthorizationCode: ((data: THAuthorizationCodeSave, req: any) => boolean)
        | ((data: THAuthorizationCodeSave, req: any) => Promise<boolean>);
    /**
     * Used by the second stage to inquire if the authorization code is still valid.
     *
     * This function also supports async calls.
     * @param data
     * @return {string|null} The authorization code if it exists or null otherwise.
     */
    getAuthorizationCode: ((data: THAuthorizationCodeAsk, req: any) => THAuthorizationCodeSave | null)
        | ((data: THAuthorizationCodeAsk, req: any) => Promise<THAuthorizationCodeSave | null>);
    /**
     * It is used by the second stage to ask for the deletion of the authorization code.
     * It should always return `true` unless the database did not delete the record,
     * in that case you must return `false`.
     *
     * This function also supports async calls.
     * @param data
     * @param req The request instance.
     * @return {boolean} True on success, false otherwise.
     */
    deleteAuthorizationCode: ((data: THAuthorizationCodeAsk, req: any) => boolean)
        | ((data: THAuthorizationCodeAsk, req: any) => Promise<boolean>);
};