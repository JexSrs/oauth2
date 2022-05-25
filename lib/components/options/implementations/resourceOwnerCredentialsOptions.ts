import {Common} from "./common";

export type ResourceOwnerCredentialsOptions = {
    /**
     * Validates user's credentials.
     * This will be used in the Resource Owner Credentials flow and nowhere else.
     * Do not include sensitive data because the result will be stored to the payload.
     * @param username
     * @param password
     * @return {any} The user's identification or null if validation failed.
     */
    validateUser: (username?: string | null, password?: string | null) => Promise<any> | any;
} & Common;