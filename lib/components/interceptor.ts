import {AuthorizationServerOptions} from "./authorizationServerOptions.js";
import EventEmitter from "events";

export type Interceptor = {
    name: string;
    function: (
        data: {
            req: any;
            serverOpts: Required<AuthorizationServerOptions>;
            response: { [key: string]: string | number };
            clientId: string;
        },
        eventEmitter: EventEmitter
    ) => object | Promise<object>;
} & ({
    endpoint: 'authorize';
    matchType: string;
} | {
    endpoint: 'token' | 'device_authorization';
    matchScope: string;
    // matchType?: string;
});