import {GenerateTokensOptions} from "../../types";

export type ResourceOwnerCredentialsOptions = {
    getClientCredentials: (req: any) => { client_id?: string | null; client_secret?: string | null; };
    validateClient: (client_id?: string | null, client_secret?: string | null) => Promise<boolean> | boolean;

    validateUser: (username?: string | null, password?: string | null) => Promise<object | null>;
} & GenerateTokensOptions;