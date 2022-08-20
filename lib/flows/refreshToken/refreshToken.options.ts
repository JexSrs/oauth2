export type RefreshTokenOptions = {
    /**
     * The error uri that will be passed with the error response.
     * It will override the one set at the AuthorizationServer constructor.
     */
    errorUri?: string;
};