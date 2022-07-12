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
     * @param req The request instance.
     * @return {any} The user's identification or null if validation failed.
     */
    validateUser: (username: string | null | undefined, password: string | null | undefined, req: any) => Promise<any> | any;
    /**
     * Validates that the client in question is registered.
     * @param client_id The client's id.
     * @param client_secret The client's secret. It will be omitted if the user is e.x. a public client.
     * @param req The request instance.
     * @return {boolean} True if validation succeeds, false otherwise.
     */
    validateClient: (client_id: string | null | undefined, client_secret: string | null | undefined, req: any) => Promise<boolean> | boolean;
};