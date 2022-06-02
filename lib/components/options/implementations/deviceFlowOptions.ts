import {DFCodeAsk, DFCodeSave} from "../../types";

export type DeviceFlowOptions = {
    /**
     * The minimum amount of time in seconds that the client
     * should wait between polling requests to the token endpoint.
     * Defaults to 5 seconds.
     */
    interval?: number;
    /**
     * The lifetime in seconds for device code and the user code.
     * Defaults to 1800 seconds (30 minutes).
     */
    expiresIn?: number;
    /**
     * If true and the device makes a request to the server, and responds with expired_token
     * then it will call the removeDevice function.
     * Defaults to true.
     */
    removeOnExpired?: boolean
    /**
     * If true and the device makes a request to the server, and responds with access_denied
     * then it will call the removeDevice function.
     * Defaults to true.
     */
    removeOnDenied?: boolean
    /**
     * The device code generator.
     * Defaults to a random arithmetical 64 character string.
     * @param client_id
     */
    deviceCodeGenerator?: (client_id: string) => string | Promise<string>;
    /**
     * The user code generator.
     * Defaults to a random arithmetical 8 character string like A1B2-C3D4.
     * @param client_id
     */
    userCodeGenerator?: (client_id: string) => string | Promise<string>;
    /**
     * The URL on the authorization server that the user should visit to begin authorization
     * It is recommended to be as compact as possible, so it will be able to be fit in
     * small screens.
     */
    verificationURI: string;
    /**
     * A function that will save the device request.
     * @param data
     * @return {boolean} True on success, false otherwise.
     */
    saveDevice: (data: DFCodeSave) => Promise<boolean> | boolean;
    /**
     * A function that will return the saved device request.
     * @param data
     * @return {DFCodeSave} The device's request or null if not found.
     */
    getDevice: (data: DFCodeAsk) => Promise<DFCodeSave | null> | DFCodeSave | null;
    /**
     * This function will remove the device request from the database.
     * @param data
     * @return {boolean} True on success, false otherwise.
     */
    removeDevice: (data: DFCodeAsk) => Promise<boolean> | boolean;
    /**
     * Validates if the client id is registered.
     * @param client_id The client's id.
     * @return {boolean} True if validation succeeds, false otherwise.
     */
    validateClient: (client_id: string) => Promise<boolean> | boolean;
    /**
     * Returns the user's identification if the has authorized the device using the user's code to the platform.
     * @param deviceCode The device's temporary code.
     * @param userCode The user's code.
     * @return {any} The user's identification.
     */
    getUser: (deviceCode: string, userCode: string) => Promise<any> | any;
    /**
     * Will return the saved bucket.
     * @param bucket The bucket string
     * @return {string|null} The bucket or the null if it has expired.
     */
    getBucket: (deviceCode: string) => Promise<string | null> | string | null;
    /**
     * Save the current bucket.
     * @param deviceCode The device code of the bucket
     * @param bucket The bucket
     * @param expiresIn The time in seconds that expires
     * @return {boolean} True if saved, false otherwise.
     */
    saveBucket: (deviceCode: string, bucket: string, expiresIn: number) => Promise<boolean> | boolean;
};