export interface AuthUser {
    id: string;
    email: string;
    password: string;
    createdAt?: Date;
    [key: string]: any;
}

export interface AuthDbAdapter {
    findUserByEmail(email: string): Promise<AuthUser | null>;
    findUserById(id: string): Promise<AuthUser | null>;
    createUser(data: { email: string; password: string }): Promise<AuthUser>;
    // TODO (for later): extend later for sessions, roles, etc.
}
