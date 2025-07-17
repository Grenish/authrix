import * as jwt from "jsonwebtoken";
import { authConfig } from "../config";

export function createToken(payload: any) {
    return jwt.sign(payload, authConfig.jwtSecret, { expiresIn: "7d" });
}
