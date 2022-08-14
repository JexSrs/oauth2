import {oicOptions} from "./oicOptions.js";
import {Interceptor} from "../../components/interceptor.js";

export function openIdConnect(opts: oicOptions): Interceptor[] {
    // Interceptor used for returning id token directly to the front channel (authorize function)
    const i1: Interceptor = {
        name: 'openid-connect',
        endpoint: 'authorize',
        matchType: 'id_token',
        function: (data, eventEmitter) => {

            return data.response;
        }
    };

    // Interceptor used for returning id token to back channel using the scope=openid+...
    const i2: Interceptor = {
        name: 'openid-connect',
        endpoint: 'token',
        matchScope: 'openid',
        function: (data, eventEmitter) => {

            return data.response;
        }
    };

    return [i1, i2];
}