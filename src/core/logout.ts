import type { Response } from "express";
import { authConfig } from "../config";

export function logout(res: Response) {
  const cookieName = authConfig.cookieName;

  res.clearCookie(cookieName, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });

  return { message: "Logged out successfully" };
}
