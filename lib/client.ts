import {ClientOptions} from "./components/clientOptions";
import {ExpressMiddleware} from "./components/types";

export class Client {

    constructor(opts: ClientOptions) {

    }

    public authenticate(): ExpressMiddleware {
        return (req, res, next) => {

        };
    }
}