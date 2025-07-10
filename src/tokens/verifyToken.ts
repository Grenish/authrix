import jwt from "jsonwebtoken";
import { authConfig } from "../config";

export interface TokenPayload {
  id: string;
  email: string;
  iat?: number;
  exp?: number;
}

export function verifyToken(token: string): TokenPayload {
  try {
    const payload = jwt.verify(token, authConfig.jwtSecret) as TokenPayload;
    return payload;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error("Token expired");
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new Error("Invalid token");
    }
    throw new Error("Token verification failed");
  }
}
