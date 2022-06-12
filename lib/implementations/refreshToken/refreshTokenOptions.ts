import {THRefreshTokenAsk} from "../../components/types";

export type RefreshTokenOptions = {
    /**
     * When the client wants to refresh the access token, this function will be called
     * to return the refresh token from the database.
     *
     * If the refresh token is not found, have expired or have been revoked then return null.
     *
     * @param data The refresh token alongside some other data that were used when saving the tokens.
     * @return {string|null} The refresh token if it exists, null otherwise.
     */
    getRefreshToken: (data: THRefreshTokenAsk) => Promise<string | null | undefined> | string | null | undefined;
    /**
     * After verifying the client and before generating the new tokens, the old tokens
     * must be revoked (deleted from the database).
     *
     * @param data The refresh token alongside some other data that were used when saving the tokens.
     * @return {boolean} True on success, false otherwise.
     */
    deleteTokens: (data: THRefreshTokenAsk) => Promise<boolean>;
    /**
     * Validates that the client in question is registered.
     * @param client_id The client's id.
     * @param client_secret The client's secret. It will be omitted if the user is e.x. a public client.
     * @return {boolean} True if validation succeeds, false otherwise.
     */
    validateClient: (client_id?: string | null, client_secret?: string | null) => Promise<boolean> | boolean;
};