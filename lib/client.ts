import {ClientOptions} from "./components/options/clientOptions";
import {ExpressMiddleware} from "./components/types";

export class Client {

    constructor(opts: ClientOptions) {

    }

    public authenticate(): ExpressMiddleware {
        return (req, res, next) => {
            // Check if we have token from another function, if not request and then authenticate.
        };
    }
}