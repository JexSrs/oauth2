import {PlusUN} from "../../components/types";

export type ResourceOwnerCredentialsOptions = {
    /**
     * It will override the `errorUri`set at the `AuthorizationServer` options.
     */
    errorUri?: string;
    /**
     * In resource owner credentials the client takes the user's credentials and sends them
     * directly to the authorization server.
     *
     * This function will validate the user's credentials and return the user's identification.
     * If the credentials are not valid then return null.
     *
     * The user's identification will be included to the tokens' payloads so:
     * * Do not include sensitive information, that you don't want others to know.
     * * The identification must be either a primitive type or valid JSON.
     * @param username
     * @param password
     * @param req The request instance.
     * @return {any} The user's identification or null if validation failed.
     */
    validateUser: ((username: PlusUN<string>, password: PlusUN<string>, req: any) => any)
        | ((username: PlusUN<string>, password: PlusUN<string>, req: any) => Promise<any>);
};