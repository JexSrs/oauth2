import {Common} from "./common";

export type ResourceOwnerCredentialsOptions = {
    validateUser: (username?: string | null, password?: string | null) => Promise<object | null>;
} & Common;