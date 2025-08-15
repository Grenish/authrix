import * as jwt from "jsonwebtoken";
import { authConfig } from "../config";

export function createToken(payload: any) {
    if (!authConfig.jwtSecret || authConfig.jwtSecret.length < 12) {
        throw new Error("Auth not initialized: jwtSecret is missing or too short. Call initAuth({ jwtSecret, db }).");
    }
    return jwt.sign(payload, authConfig.jwtSecret, { expiresIn: "7d" });
}
