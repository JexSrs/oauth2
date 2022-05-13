import {DatabaseFunctions, THAuthorizationCodeSave, THTokenSave} from "../components/serverOptions";

export function memory(): DatabaseFunctions {
    const tokenDB: THTokenSave[] = [];
    const authCodeDB: THAuthorizationCodeSave[] = [];
    return {
        saveToken: async data => {
            tokenDB.push(data);
            return true;
        },
        loadAccessToken: async data => [...tokenDB].find(a =>
            data.accessToken === a.accessToken
            && data.accessTokenExpiresAt === a.accessTokenExpiresAt)?.accessToken,
        loadRefreshToken: async data => [...tokenDB].find(a =>
            data.refreshToken === a.refreshToken
            && data.refreshTokenExpiresAt === a.refreshTokenExpiresAt)?.refreshToken,
        removeToken: async data => {
            let index = tokenDB.findIndex(a =>
                data.accessToken === a.accessToken
                && data.accessTokenExpiresAt === a.accessTokenExpiresAt);
            if(index !== -1)
                tokenDB.splice(index, 1);
            return true;
        },
        saveAuthorizationCode: async data => {
            authCodeDB.push(data);
            return true;
        },
        loadAuthorizationCode: async data => [...authCodeDB].find(a =>
            data.authorizationCode === a.authorizationCode
            && data.expiresAt === a.expiresAt),
        removeAuthorizationCode: async data => {
            let index = authCodeDB.findIndex(a =>
                data.authorizationCode === a.authorizationCode
                && data.expiresAt === a.expiresAt);
            if(index !== -1)
                authCodeDB.splice(index, 1);
            return true;
        },
    };
}