import {THAuthorizationCodeAsk, THAuthorizationCodeSave} from "../../components/types";

export type AuthorizationCodeOptions = {
    /**
     * PKCE (Proof Key for Code Exchange) is an extension to the authorization code flow
     * that enhances protection. More specifically ts to prevents CSRF and authorization code injection attacks.
     *
     * If you enable PKCE the fields code_challenge and code_challenge_method must be included in the request.
     *
     * Defaults to true.
     */
    usePKCE?: boolean;
    /**
     * The code challenge methods the client is allowed to use.
     *
     * Note this is used only if PKCE is enabled.
     *
     * Defaults to ['S256', 'plain'].
     */
    validCodeChallengeMethods?: string[];
    /**
     * This function will take the code verifier and hash it using the code challenge method.
     *
     * Defaults to S256 and plain methods hashing.
     * @param code The code verifier.
     * @param method The code challenge method.
     */
    hashCodeChallenge?: (code: string, method: string) => string | Promise<string>,
    /**
     * The authorization code's lifetime in seconds.
     * Defaults to 60 seconds (1 minute).
     */
    authorizationCodeLifetime?: number;
    /**
     * When generating the authorization code this function will be called
     * to save all the given data. They will be asked during the second phase of the authorization code flow.
     *
     * Because this is a short-lived code, it recommended to save it in cache (like redis)
     * and expire it after authorizationCodeLifetime seconds (or data.expiresAt - Math.floor(Date.now() / 1000) seconds).
     *
     * @param data The data that needs to be saved.
     * @param req The request instance.
     * @return {boolean} True on success, false otherwise.
     */
    saveAuthorizationCode: (data: THAuthorizationCodeSave, req: any) => Promise<boolean> | boolean;
    /**
     * This function will ask all the data that was saved during the first phase of the authorization code flow.
     * @param data
     * @return {string|null} The authorization code if it exists or null otherwise.
     */
    getAuthorizationCode: (data: THAuthorizationCodeAsk, req: any) => Promise<THAuthorizationCodeSave | null> | THAuthorizationCodeSave | null;
    /**
     * This function will be called after verifying the authorization code at the second phase.
     *
     * It is extremely important to delete the authorization code after using once, so it will not be used twice.
     * If the authorization code is used more than once, it is recommended to treat it as an attack (leaked code)
     * and revoke all the generated tokens.
     *
     * @param data
     * @param req The request instance.
     * @return {boolean} True on success, false otherwise.
     */
    deleteAuthorizationCode: (data: THAuthorizationCodeAsk, req: any) => Promise<boolean> | boolean;
    /**
     * Validates that the client in question is registered.
     * @param client_id The client's id.
     * @param client_secret The client's secret. It will be omitted if the user is e.x. a public client.
     * @param req The request instance.
     * @return {boolean} True if validation succeeds, false otherwise.
     */
    validateClient: (client_id: string | null | undefined, client_secret: string | null | undefined, req: any) => Promise<boolean> | boolean;
};