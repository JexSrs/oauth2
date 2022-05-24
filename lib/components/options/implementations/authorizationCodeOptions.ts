import {THAuthorizationCodeAsk, THAuthorizationCodeSave} from "../../types";

export type AuthorizationCodeOptions = {
    usePKCE: boolean;
    allowCodeChallengeMethodPlain: boolean;

    authorizationCodeLifetime: number;
    saveAuthorizationCode: (data: THAuthorizationCodeSave) => Promise<boolean> | boolean;

    getClientCredentials: (req: any) => { client_id?: string | null; client_secret?: string | null; };
    validateClient: (client_id?: string | null, client_secret?: string | null) => Promise<boolean> | boolean;
    getAuthorizationCode: (data: THAuthorizationCodeAsk) => Promise<THAuthorizationCodeSave | null> | THAuthorizationCodeSave | null;
    deleteAuthorizationCode: (data: THAuthorizationCodeAsk) => Promise<boolean> | boolean;
};