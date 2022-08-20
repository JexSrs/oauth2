import {AuthorizationServerOptions} from "./authorizationServer.options.js";
import EventEmitter from "events";

export type Interceptor = {
    name: string;
    endpoint: 'authorize' | 'token' | 'device_authorization';
    function: (
        data: {
            req: any;
            serverOpts: Required<AuthorizationServerOptions>;
            response: { [key: string]: string | number };
            clientId: string;
        },
        eventEmitter: EventEmitter
    ) => object | Promise<object>;
};