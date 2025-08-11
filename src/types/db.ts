export interface AuthUser {
  id: string;
  email: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  fullName?: string;
  profilePicture?: string;
  password: string;
  createdAt?: Date;
  emailVerified?: boolean;
  emailVerifiedAt?: Date;
  twoFactorEnabled?: boolean;
  [key: string]: any;
}

export interface TwoFactorCode {
  id: string;
  userId: string;
  code: string;
  hashedCode: string;
  type: "email_verification" | "password_reset" | "login_verification";
  expiresAt: Date;
  createdAt: Date;
  attempts: number;
  isUsed: boolean;
  metadata?: {
    email?: string;
    ipAddress?: string;
    userAgent?: string;
  };
}

export interface AuthDbAdapter {
  findUserByEmail(email: string): Promise<AuthUser | null>;
  findUserById(id: string): Promise<AuthUser | null>;
  findUserByUsername(username: string): Promise<AuthUser | null>;
  createUser(data: {
    email: string;
    password: string;
    username?: string;
    firstName?: string;
    lastName?: string;
    fullName?: string;
    profilePicture?: string;
  }): Promise<AuthUser>;

  // Optional 2FA methods - implement these for 2FA support
  updateUser?(id: string, data: Partial<AuthUser>): Promise<AuthUser>;
  storeTwoFactorCode?(code: TwoFactorCode): Promise<void>;
  getTwoFactorCode?(codeId: string): Promise<TwoFactorCode | null>;
  updateTwoFactorCode?(
    codeId: string,
    updates: Partial<TwoFactorCode>
  ): Promise<void>;
  getUserTwoFactorCodes?(
    userId: string,
    type?: string
  ): Promise<TwoFactorCode[]>;
  cleanupExpiredTwoFactorCodes?(): Promise<number>;

  // TODO (for later): extend later for sessions, roles, etc.
}
