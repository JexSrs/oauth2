export type ResourceOwnerCredentialsOptions = {
    /**
     * In resource owner credentials the client takes the user's credentials and sends them
     * directly to the authorization server.
     *
     * This function will validate the user's credentials and return the user's identification.
     * If the credentials are not valid then return null.
     *
     * The user's identification will be included to the tokens' payloads so:
     * * Do not include sensitive information, that you don't want others to know.
     * * The identification must be either a primitive type or valid JSON.
     *
     * @param username
     * @param password
     * @return {any} The user's identification or null if validation failed.
     */
    validateUser: (username?: string | null, password?: string | null) => Promise<any> | any;
    /**
     * Validates that the client in question is registered.
     * @param client_id The client's id.
     * @param client_secret The client's secret. It will be omitted if the user is e.x. a public client.
     * @return {boolean} True if validation succeeds, false otherwise.
     */
    validateClient: (client_id?: string | null, client_secret?: string | null) => Promise<boolean> | boolean;
};