import {THRefreshTokenAsk} from "../../types";
import {Common} from "./common";

export type RefreshTokenOptions = {
    /**
     * The function that will load th refreshToken from database.
     * @param data
     * @return {string|null} The refresh token, null if it does not exist.
     */
    getRefreshToken: (data: THRefreshTokenAsk) => Promise<string | null | undefined> | string | null | undefined;
    /**
     * The function that will remove the access & refresh tokens from the database.
     * @param data
     * @return {boolean} True on success, false otherwise.
     */
    deleteTokens: (data: THRefreshTokenAsk) => Promise<boolean>;
} & Common;