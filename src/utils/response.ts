import type { Response, NextFunction, Request } from "express";
import { AuthrixError } from "./errors";

interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: {
        message: string;
    };
}

export function sendSuccess<T>(res: Response, data: T, statusCode = 200) {
    const response: ApiResponse<T> = {
        success: true,
        data,
    };
    res.status(statusCode).json(response);
}

export function sendError(res: Response, message: string, statusCode = 500) {
    const response: ApiResponse<null> = {
        success: false,
        error: {
            message,
        },
    };
    res.status(statusCode).json(response);
}

export function errorHandler(
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction
) {
    if (err instanceof AuthrixError) {
        return sendError(res, err.message, err.statusCode);
    }

    // Log unexpected errors for debugging
    console.error("Unexpected error:", err);

    // Send a generic server error response to the client
    return sendError(res, "An unexpected internal server error occurred.", 500);
}
