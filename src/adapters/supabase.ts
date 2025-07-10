import type { AuthDbAdapter, AuthUser } from "../types/db";
import { createClient, SupabaseClient } from "@supabase/supabase-js";

// Read from environment
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const TABLE_NAME = process.env.SUPABASE_AUTH_TABLE || "users";

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  throw new Error("SUPABASE_URL and SUPABASE_ANON_KEY environment variables are required");
}

const supabase: SupabaseClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

export const supabaseAdapter: AuthDbAdapter = {
  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const normalizedEmail = email.toLowerCase().trim();
    
    const { data, error } = await supabase
      .from(TABLE_NAME)
      .select("*")
      .eq("email", normalizedEmail)
      .single();

    if (error || !data) return null;

    return {
      id: data.id.toString(),
      email: data.email,
      password: data.password,
      createdAt: data.created_at ? new Date(data.created_at) : undefined,
    };
  },

  async findUserById(id: string): Promise<AuthUser | null> {
    const { data, error } = await supabase
      .from(TABLE_NAME)
      .select("*")
      .eq("id", id)
      .single();

    if (error || !data) return null;

    return {
      id: data.id.toString(),
      email: data.email,
      password: data.password,
      createdAt: data.created_at ? new Date(data.created_at) : undefined,
    };
  },

  async createUser({ email, password }): Promise<AuthUser> {
    const normalizedEmail = email.toLowerCase().trim();
    const now = new Date();

    const { data, error } = await supabase
      .from(TABLE_NAME)
      .insert({
        email: normalizedEmail,
        password,
        created_at: now.toISOString(),
      })
      .select()
      .single();

    if (error || !data) {
      throw new Error(`Failed to create user: ${error?.message || "Unknown error"}`);
    }

    return {
      id: data.id.toString(),
      email: data.email,
      password: data.password,
      createdAt: new Date(data.created_at),
    };
  },
};
