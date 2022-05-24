export type ClientCredentialsOptions = {
    getClientCredentials: (req: any) => { client_id?: string | null; client_secret?: string | null; };
    validateClient: (client_id?: string | null, client_secret?: string | null) => Promise<boolean> | boolean;
};