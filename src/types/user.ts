export const USER_COLLECTION = process.env.MONGO_USER_COLLECTION || "users";

export interface User {
    id: string;
    email: string;
    password: string;
    createdAt: Date;
}
