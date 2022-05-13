import {DatabaseFunctions, THAuthorizationCodeSave, THTokenSave} from "../components/serverOptions";

export function memory(): DatabaseFunctions {
    const tokenDB: THTokenSave[] = [];
    const authCodeDB: THAuthorizationCodeSave[] = [];
    return {
        saveTokens: async data => {
            tokenDB.push(data);
            return true;
        },
        getAccessToken: async data => [...tokenDB].find(a => data.accessToken === a.accessToken)?.accessToken,
        getRefreshToken: async data => [...tokenDB].find(a => data.refreshToken === a.refreshToken
            && data.clientId === a.clientId)?.refreshToken,
        deleteTokens: async data => {
            let index = tokenDB.findIndex(a =>
                data.refreshToken === a.refreshToken && data.clientId === a.clientId);
            if(index !== -1)
                tokenDB.splice(index, 1);
            return true;
        },
        saveAuthorizationCode: async data => {
            authCodeDB.push(data);
            return true;
        },
        getAuthorizationCode: async data => [...authCodeDB].find(a => data.authorizationCode === a.authorizationCode),
        deleteAuthorizationCode: async data => {
            let index = authCodeDB.findIndex(a => data.authorizationCode === a.authorizationCode);
            if(index !== -1)
                authCodeDB.splice(index, 1);
            return true;
        },
    };
}