export type ClientCredentialsOptions = {
    /**
     * Validates that the client in question is registered.
     * @param client_id The client's id.
     * @param client_secret The client's secret. It will be omitted if the user is e.x. a public client.
     * @param req The request instance.
     * @return {boolean} True if validation succeeds, false otherwise.
     */
    validateClient: (client_id: string | null | undefined, client_secret: string | null | undefined, req: any) => Promise<boolean> | boolean;
};