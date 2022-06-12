import {DFCodeAsk, DFCodeSave} from "../../components/types";

export type DeviceFlowOptions = {
    /**
     * The minimum amount of seconds that the client should wait
     * between the polling requests to the token endpoint.
     *
     * In case the client spams the token endpoint an error
     * response 'slow_down' will be returned.
     *
     * Defaults to 5 seconds.
     */
    interval?: number;
    /**
     * The seconds where the user's code will be valid.
     *
     * Defaults to 1800 seconds (30 minutes).
     */
    expiresIn?: number;
    /**
     * The device code generator.
     *
     * Defaults to a random arithmetical 64 character string.
     * @param client_id
     */
    deviceCodeGenerator?: (client_id: string) => string | Promise<string>;
    /**
     * The user code generator.
     *
     * Defaults to a random arithmetical 8 capital character string like A1B2-C3D4.
     * @param client_id
     */
    userCodeGenerator?: (client_id: string) => string | Promise<string>;
    /**
     * The url that the user should visit to authorize the client.
     *
     * It is recommended to be as compact as possible, so it will be able to be fit in
     * small screens.
     */
    verificationURI: string;
    /**
     * When the client asks for the device and user code this function
     * will be called to save the data. The status will be set to 'pending'.
     *
     * It is recommended to save them in cache (like redis) because they will
     * be requested in short time frames.
     *
     * @param data
     * @return {boolean} True on success, false otherwise.
     */
    saveDevice: (data: DFCodeSave) => Promise<boolean> | boolean;
    /**
     * When the client starts doing the polling requests, this function will be called
     * to retrieve the data saved before.
     *
     * If the status is changed from 'pending' to 'completed' then the flow will continue
     * and check if the user authorized the request.
     *
     * @param data
     * @return {DFCodeSave} The device's request or null if not found.
     */
    getDevice: (data: DFCodeAsk) => Promise<DFCodeSave | null> | DFCodeSave | null;
    /**
     * When the request is marked as 'completed' this function will be called
     * to remove the saved data (if not already expired).
     *
     * @param data
     * @return {boolean} True on success, false otherwise.
     */
    removeDevice: (data: DFCodeAsk) => Promise<boolean> | boolean;
    /**
     * Validates that the client in question is registered.
     * @param client_id The client's id.
     * @return {boolean} True if validation succeeds, false otherwise.
     */
    validateClient: (client_id: string) => Promise<boolean> | boolean;
    /**
     * After the request is marked as 'completed', the user may have accepted or declined the request/
     *
     * If the user:
     * * Accepts the request, you have to provide an identification.
     * * Declines the request, you have to return null.
     *
     * @param deviceCode The device's code.
     * @param userCode The user's code.
     * @return {any} The user's identification.
     */
    getUser: (deviceCode: string, userCode: string) => Promise<any> | any;
    /**
     * This function will be used to rate limit the polling requests made by the client.
     *
     * When the client makes a request it will create a bucket and save it.
     * If the bucket is found after 'interval' seconds (not expired),
     * it will respond with an error 'slow_down'.
     *
     * It is recommended to save it in cache (like redis) because they will
     * be requested in short time frames.
     *
     * @param deviceCode The device's code.
     * @param bucket The bucket.
     * @param expiresIn The time in seconds that expires.
     * @return {boolean} True if saved, false otherwise.
     */
    saveBucket: (deviceCode: string, bucket: string, expiresIn: number) => Promise<boolean> | boolean;
    /**
     * This function will be used to rate limit the polling requests made by the client.
     *
     * It will request the bucket that saved before and check if it has expired.
     * If the bucket is not found (because it has expired) return null.
     *
     * The bucket is created using a JWT, so even if you provide an expired bucket
     * the flow will still verify the expiration time.
     *
     * @param bucket The bucket.
     * @return {string|null} The bucket or the null if it has expired.
     */
    getBucket: (deviceCode: string) => Promise<string | null> | string | null;
};