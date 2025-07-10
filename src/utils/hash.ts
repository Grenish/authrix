import bcrypt from "bcryptjs";

export async function hashPassword(password: string) {
    return bcrypt.hash(password, 12);
}
