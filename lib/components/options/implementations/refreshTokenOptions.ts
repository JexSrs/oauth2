import {THRefreshTokenAsk} from "../../types";
import {Common} from "./common";

export type RefreshTokenOptions = {
    getRefreshToken: (data: THRefreshTokenAsk) => Promise<string | null | undefined> | string | null | undefined;
    deleteTokens: (data: THRefreshTokenAsk) => Promise<boolean>;
} & Common;