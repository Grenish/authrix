import type { AuthDbAdapter, AuthUser, TwoFactorCode } from "../types/db";

type PrismaClientType = any;

interface PrismaAdapterOptions {
  client?: PrismaClientType; // Optional: pass an existing PrismaClient instance
  modelNames?: {
    user?: string; // default: User
    twoFactor?: string; // default: TwoFactorCode
  };
}

function getModel<T = any>(client: PrismaClientType, name: string): T {
  if (!client[name]) {
    throw new Error(`Prisma model "${name}" not found on PrismaClient`);
  }
  return client[name] as T;
}

function pickUserFields(user: any): AuthUser {
  if (!user) return null as any;
  return {
    id: String(user.id),
    email: user.email,
    username: user.username ?? undefined,
    firstName: user.firstName ?? undefined,
    lastName: user.lastName ?? undefined,
    fullName: user.fullName ?? undefined,
    profilePicture: user.profilePicture ?? undefined,
    password: user.password,
    createdAt: user.createdAt ?? undefined,
    emailVerified: user.emailVerified ?? undefined,
    emailVerifiedAt: user.emailVerifiedAt ?? undefined,
    twoFactorEnabled: user.twoFactorEnabled ?? undefined,
  };
}

function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

function normalizeUsername(username?: string): string | undefined {
  return username ? username.toLowerCase().trim() : undefined;
}

export function createPrismaAdapter(
  options: PrismaAdapterOptions = {}
): AuthDbAdapter {
  let prisma: PrismaClientType | null = options.client ?? null;
  const modelNames = {
    user: options.modelNames?.user ?? "user",
    twoFactor: options.modelNames?.twoFactor ?? "twoFactorCode",
  };

  async function ensureClient(): Promise<PrismaClientType> {
    if (prisma) return prisma;
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { PrismaClient } = require("@prisma/client");
      prisma = new PrismaClient();
      return prisma;
    } catch (e) {
      throw new Error(
        "@prisma/client is not installed. Please add it to your project to use the Prisma adapter."
      );
    }
  }

  return {
    async findUserByEmail(email: string): Promise<AuthUser | null> {
      const client = await ensureClient();
      const userModel = getModel(client, modelNames.user);
      const user = await userModel.findUnique({
        where: { email: normalizeEmail(email) },
      });
      return user ? pickUserFields(user) : null;
    },

    async findUserById(id: string): Promise<AuthUser | null> {
      const client = await ensureClient();
      const userModel = getModel(client, modelNames.user);
      const user = await userModel.findUnique({ where: { id } });
      return user ? pickUserFields(user) : null;
    },

    async findUserByUsername(username: string): Promise<AuthUser | null> {
      const client = await ensureClient();
      const userModel = getModel(client, modelNames.user);
      const user = await userModel.findUnique({
        where: { username: normalizeUsername(username) },
      });
      return user ? pickUserFields(user) : null;
    },

    async createUser({
      email,
      password,
      username,
      firstName,
      lastName,
      fullName,
      profilePicture,
    }): Promise<AuthUser> {
      const client = await ensureClient();
      const userModel = getModel(client, modelNames.user);
      try {
        const user = await userModel.create({
          data: {
            email: normalizeEmail(email),
            password,
            username: normalizeUsername(username),
            firstName: firstName?.trim() ?? null,
            lastName: lastName?.trim() ?? null,
            fullName: fullName?.trim() ?? null,
            profilePicture: profilePicture?.trim?.() ?? profilePicture ?? null,
          },
        });
        return pickUserFields(user);
      } catch (error: any) {
        // Prisma unique constraint errors: code P2002
        if (error?.code === "P2002" && Array.isArray(error?.meta?.target)) {
          const field = error.meta.target[0];
          const value = field === "email" ? email : username;
          throw new Error(
            `${field.charAt(0).toUpperCase() + field.slice(1)} "${value}" is already in use`
          );
        }
        throw new Error(
          `Failed to create user: ${error?.message || String(error)}`
        );
      }
    },

    async updateUser(id: string, data: Partial<AuthUser>): Promise<AuthUser> {
      const client = await ensureClient();
      const userModel = getModel(client, modelNames.user);
      try {
        const updated = await userModel.update({
          where: { id },
          data: {
            email:
              data.email !== undefined ? normalizeEmail(data.email) : undefined,
            password: data.password,
            emailVerified: data.emailVerified,
            emailVerifiedAt: data.emailVerifiedAt,
            twoFactorEnabled: data.twoFactorEnabled,
            username:
              data.username !== undefined
                ? normalizeUsername(data.username)
                : undefined,
            firstName: data.firstName?.trim(),
            lastName: data.lastName?.trim(),
            fullName: data.fullName?.trim(),
            profilePicture:
              data.profilePicture?.trim?.() ?? data.profilePicture,
          },
        });
        return pickUserFields(updated);
      } catch (error: any) {
        if (error?.code === "P2002" && Array.isArray(error?.meta?.target)) {
          const field = error.meta.target[0];
          const value = (data as any)[field];
          throw new Error(
            `${field.charAt(0).toUpperCase() + field.slice(1)} "${value}" is already in use`
          );
        }
        if (error?.code === "P2025") {
          throw new Error("User not found");
        }
        throw error;
      }
    },

    // 2FA support (optional)
    async storeTwoFactorCode(code: TwoFactorCode): Promise<void> {
      const client = await ensureClient();
      const twoFactorModel = getModel(client, modelNames.twoFactor);
      await twoFactorModel.create({ data: code });
    },

    async getTwoFactorCode(codeId: string): Promise<TwoFactorCode | null> {
      const client = await ensureClient();
      const twoFactorModel = getModel(client, modelNames.twoFactor);
      const code = await twoFactorModel.findUnique({ where: { id: codeId } });
      return code ?? null;
    },

    async updateTwoFactorCode(
      codeId: string,
      updates: Partial<TwoFactorCode>
    ): Promise<void> {
      const client = await ensureClient();
      const twoFactorModel = getModel(client, modelNames.twoFactor);
      await twoFactorModel.update({ where: { id: codeId }, data: updates });
    },

    async getUserTwoFactorCodes(
      userId: string,
      type?: string
    ): Promise<TwoFactorCode[]> {
      const client = await ensureClient();
      const twoFactorModel = getModel(client, modelNames.twoFactor);
      const where: any = {
        userId,
        isUsed: false,
        expiresAt: { gt: new Date() },
      };
      if (type) where.type = type;
      return await twoFactorModel.findMany({
        where,
        orderBy: { createdAt: "desc" },
        take: 10,
      });
    },

    async cleanupExpiredTwoFactorCodes(): Promise<number> {
      const client = await ensureClient();
      const twoFactorModel = getModel(client, modelNames.twoFactor);
      const result = await twoFactorModel.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            {
              isUsed: true,
              createdAt: { lt: new Date(Date.now() - 24 * 60 * 60 * 1000) },
            },
          ],
        },
      });
      return result.count ?? 0;
    },
  };
}

export default createPrismaAdapter;
