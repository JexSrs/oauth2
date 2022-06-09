import {THAuthorizationCodeAsk, THAuthorizationCodeSave} from "../../types";
import {Common} from "./common";

export type AuthorizationCodeOptions = {
    /**
     * If true the PKCE (Proof Key for Code Exchange) extension will be used.
     * That means that during authorization the fields code_challenge and code_challenge_method
     * must be included.
     * Defaults to true.
     */
    usePKCE?: boolean;
    /**
     * The valid code challenge methods
     * Defaults to ['S256', 'plain']
     */
    validCodeChallengeMethods?: string[];
    /**
     * A function that will hash a code with the given method.
     * Defaults to S256 and plain methods hashing.
     * @param code
     * @param method
     */
    hashCodeChallenge?: (code: string, method: string) => string | Promise<string>,
    /**
     * The authorization code's lifetime in seconds.
     * Defaults to 60 seconds (1 minute).
     */
    authorizationCodeLifetime?: number;
    /**
     * The function that will save the authorization code to the database.
     * @param data The data that needs to be saved.
     * @return {boolean} True on success, false otherwise.
     */
    saveAuthorizationCode: (data: THAuthorizationCodeSave) => Promise<boolean> | boolean;
    /**
     * The function that will load the authorization code from database.
     * You have to return all the fields that was saved from saveAuthorizationCode call.
     * @param data
     * @return {string|null} The authorization code if it exists or null otherwise.
     */
    getAuthorizationCode: (data: THAuthorizationCodeAsk) => Promise<THAuthorizationCodeSave | null> | THAuthorizationCodeSave | null;
    /**
     * The function that will remove the authorization code from the database.
     * @param data
     * @return {boolean} True on success, false otherwise.
     */
    deleteAuthorizationCode: (data: THAuthorizationCodeAsk) => Promise<boolean> | boolean;
} & Common;