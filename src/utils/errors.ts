export class AuthrixError extends Error {
    statusCode: number;

    constructor(message: string, statusCode: number) {
        super(message);
        this.statusCode = statusCode;
        this.name = this.constructor.name;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export class BadRequestError extends AuthrixError {
    constructor(message = "Bad Request") {
        super(message, 400);
    }
}

export class UnauthorizedError extends AuthrixError {
    constructor(message = "Authentication required") {
        super(message, 401);
    }
}

export class ForbiddenError extends AuthrixError {
    constructor(message = "Forbidden") {
        super(message, 403);
    }
}

export class NotFoundError extends AuthrixError {
    constructor(message = "Not Found") {
        super(message, 404);
    }
}

export class ConflictError extends AuthrixError {
    constructor(message = "Conflict") {
        super(message, 409);
    }
}

export class InternalServerError extends AuthrixError {
    constructor(message = "Internal Server Error") {
        super(message, 500);
    }
}
