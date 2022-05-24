export type Common = {
    /**
     * Override client credentials location.
     * If one of the credentials is not found return undefined, null or empty string.
     * Default to authorization header: Basic <BASE64({CLIENT ID}:{CLIENT SECRET})>
     * @param req The request instance.
     * @return {object} the client_id and client_secret.
     */
    getClientCredentials: (req: any) => { client_id?: string | null; client_secret?: string | null; };
    /**
     * Validates that the client in question is registered.
     * @param client_id The client's id.
     * @param client_secret The client's secret. It will be omitted if the user is e.x. a public client.
     * @return {boolean} true if validation succeeds, false otherwise.
     */
    validateClient: (client_id?: string | null, client_secret?: string | null) => Promise<boolean> | boolean;
}