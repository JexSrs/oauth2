import {GenerateTokensOptions, THRefreshTokenAsk} from "../../types";

export type RefreshTokenOptions = {
    getClientCredentials: (req: any) => { client_id?: string | null; client_secret?: string | null; };
    validateClient: (client_id?: string | null, client_secret?: string | null) => Promise<boolean> | boolean;

    getRefreshToken: (data: THRefreshTokenAsk) => Promise<string | null | undefined> | string | null | undefined;
    deleteTokens: (data: THRefreshTokenAsk) => Promise<boolean>;
} & GenerateTokensOptions;