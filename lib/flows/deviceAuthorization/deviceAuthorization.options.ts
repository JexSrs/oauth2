import {DFCodeAsk, DFCodeSave} from "../../components/general.types.js";

export type DeviceAuthorizationOptions = {
    /**
     * The minimum amount of seconds that the client should wait between the polling requests to
     * the token endpoint. It defaults to `5 sec`.
     *
     * In case the client did not take into account the interval the token endpoint will
     * respond with the `slow_down` error.
     */
    interval?: number;
    /**
     * The seconds until the user's code expires.
     * It defaults to `1800 sec` = 30 minutes.
     */
    expiresIn?: number;
    /**
     * The device code generator. It will override the default generator with a custom one.
     *
     * This function also supports async calls.
     * @param client_id
     */
    deviceCodeGenerator?: ((client_id: any, req: any) => string)
        | ((client_id: any, req: any) => Promise<string>);
    /**
     * The user code generator. It will override the default generator with a custom one.
     *
     * This function also supports async calls.
     * @param client_id
     */
    userCodeGenerator?: ((client_id: any, req: any) => string)
        | ((client_id: any, req: any) => Promise<string>);
    /**
     * The error uri that will be passed with the error response.
     * It will override the one set at the AuthorizationServer constructor.
     */
    errorUri?: string;
    /**
     * A verification URI that includes the "user_code" (or
     * other information with the same function as the "user_code"),
     * which is designed for non-textual transmission.
     *
     * The substring `{user-code}` will be replaced in this url with the
     * generated user code. For example, `https://example.com?userCode={user-code}`
     * will be transformed to this `https://example.com?userCode=ABCD-EFGH`.
     */
    verificationURIComplete?: string;
    /**
     * The url that the user should visit to authorize the client. In this url the
     * user will have to enter the `user code`. If the user code is valid you should change
     * the record status from `pending` to `completed`.
     *
     * It is recommended to be as compact as possible, so it will be able to be fit in small screens.
     */
    verificationURI: string;
    /**
     * Used from first stage to save the generated device record with status set as `pending`.
     *
     * It is recommended to save the record in cache (like `redis`) because it will
     * be requested repeatedly in short time frames.
     *
     * This function also supports async calls.
     * @param data
     * @param req The request instance.
     * @return {boolean} True on success, false otherwise.
     */
    saveDevice: ((data: DFCodeSave, req: any) => boolean)
        | ((data: DFCodeSave, req: any) => Promise<boolean>);
    /**
     * Used at the second stage to inquire if a device record exists and if it does
     * what is its status.
     *
     * If the status is changed from `pending` to `completed` then the flow will continue
     * and check if the user authorized the request.
     *
     * This function also supports async calls.
     * @param data
     * @param req The request instance.
     * @return {DFCodeSave} The device's request or null if not found.
     */
    getDevice: ((data: DFCodeAsk, req: any) => DFCodeSave | null)
        | ((data: DFCodeAsk, req: any) => Promise<DFCodeSave | null>);
    /**
     * Used at the second stage to ask to delete the device record.
     * It should always return `true` unless the database did not delete the record,
     * in that case you must return `false`.
     *
     * This function also supports async calls.
     * @param data
     * @param req The request instance.
     * @return {boolean} True on success, false otherwise.
     */
    removeDevice: ((data: DFCodeAsk, req: any) => boolean)
        | ((data: DFCodeAsk, req: any) => Promise<boolean>);
    /**
     * Used at the second stage to inquire if the user authorized the request
     * and get the user's identification.
     *
     * If the user declines the request, you have to return null.
     *
     * This function also supports async calls.
     * @param deviceCode The device's code.
     * @param userCode The user's code.
     * @param req The request instance.
     * @return {any} The user's identification.
     */
    getUser: ((deviceCode: string, userCode: string, req: any) => any)
        | ((deviceCode: string, userCode: string, req: any) => Promise<any>);
    /**
     * Used at the second stage to rate limit the polling requests made by the client.
     * It should always return `true` unless the database did not save the record,
     * in that case you must return `false`.
     *
     * It is recommended to save it in cache (like `redis`) because they will be requested
     * repeatedly in short time frames.
     *
     * This function also supports async calls.
     * @param deviceCode The device's code.
     * @param bucket The bucket.
     * @param expiresIn The time in seconds that expires.
     * @param req The request instance.
     * @return {boolean} True if saved, false otherwise.
     */
    saveBucket: ((deviceCode: string, bucket: string, expiresIn: number, req: any) => boolean)
        | ((deviceCode: string, bucket: string, expiresIn: number, req: any) => Promise<boolean>);
    /**
     * Used by the second stage to rate limit the polling requests made by the client.
     *
     * It will request the bucket that saved before and check if it has expired. If the bucket is not found
     * (because it has expired), return null.
     *
     * The bucket is created using a JWT, so even if you provide an expired bucket the flow will still
     * verify the expiration time.
     *
     * This function also supports async calls.
     * @param bucket The bucket.
     * @param req The request instance.
     * @return {string|null} The bucket or the null if it has expired.
     */
    getBucket: ((deviceCode: string, req: any) => string | null)
        | ((deviceCode: string, req: any) => Promise<string | null>);
};