import {oicOptions} from "./oicOptions.js";
import {Interceptor} from "../../components/interceptor.js";

export function openIdConnect(opts: oicOptions): Interceptor[] {
    // TODO - Think how to call the first interceptor alone without a flow accompanying it.

    return [
        // Interceptor used for returning id_token directly to the front channel (authorize function)
        {
            name: 'openid-connect',
            endpoint: 'authorize',
            matchType: 'id_token',
            function: (data, eventEmitter) => {

                return data.response;
            }
        },
        // Interceptor used for returning id_token to back channel using the scope=openid+...
        {
            name: 'openid-connect',
            endpoint: 'token',
            matchScope: 'openid',
            function: (data, eventEmitter) => {

                return data.response;
            }
        }
    ];
}