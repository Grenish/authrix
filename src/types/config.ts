import dotenv from "dotenv";

dotenv.config();

interface AuthConfig {
  jwtSecret: string;
  cookieName: string;
  tokenExpirySeconds: number;
}

const JWT_SECRET = process.env.JWT_SECRET;
const COOKIE_NAME = process.env.COOKIE_NAME || "auth_token";
const TOKEN_EXPIRY_SECONDS = parseInt(process.env.TOKEN_EXPIRY_SECONDS || "604800", 10); // 7 days default

if (!JWT_SECRET) {
  throw new Error("Missing JWT_SECRET environment variable");
}

export const authConfig: AuthConfig = {
  jwtSecret: JWT_SECRET,
  cookieName: COOKIE_NAME,
  tokenExpirySeconds: TOKEN_EXPIRY_SECONDS,
};
