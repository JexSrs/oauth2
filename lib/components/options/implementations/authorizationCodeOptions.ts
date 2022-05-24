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
     * Only for enabled PKCE.
     * If true it will allow code challenge method 'plain' and will not enforce
     * S256 as mandatory.
     * Defaults to false.
     */
    allowCodeChallengeMethodPlain?: boolean;
    /**
     * The authorization code's lifetime in seconds.
     * Defaults to 60 seconds (1 minute).
     */
    authorizationCodeLifetime?: number;
    /**
     * The function that will save the authorization code to the database.
     * @param data The data that needs to be saved.
     * @return {boolean} true on succeed, false otherwise.
     */
    saveAuthorizationCode: (data: THAuthorizationCodeSave) => Promise<boolean> | boolean;
    /**
     * The function that will load the authorization code from database.
     * @param data
     * @return {string|null} The authorization code if it exists or null otherwise.
     */
    getAuthorizationCode: (data: THAuthorizationCodeAsk) => Promise<THAuthorizationCodeSave | null> | THAuthorizationCodeSave | null;
    /**
     * The function that will remove the authorization code from the database.
     * @param data
     * @return {boolean} true on succeed, false otherwise.
     */
    deleteAuthorizationCode: (data: THAuthorizationCodeAsk) => Promise<boolean> | boolean;
} & Common;