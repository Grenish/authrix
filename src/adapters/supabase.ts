import type { AuthDbAdapter, AuthUser } from "../types/db";
import { createClient, SupabaseClient } from "@supabase/supabase-js";

// Lazy-load environment variables and client to avoid errors when adapter is not used
let supabaseClient: SupabaseClient | null = null;

function getSupabaseClient(): SupabaseClient {
  if (!supabaseClient) {
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
      throw new Error("SUPABASE_URL and SUPABASE_ANON_KEY environment variables are required");
    }

    supabaseClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  }
  
  return supabaseClient;
}

function getTableName(): string {
  return process.env.SUPABASE_AUTH_TABLE || "users";
}

export const supabaseAdapter: AuthDbAdapter = {
  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const supabase = getSupabaseClient();
    const tableName = getTableName();
    const normalizedEmail = email.toLowerCase().trim();
    
    const { data, error } = await supabase
      .from(tableName)
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
    const supabase = getSupabaseClient();
    const tableName = getTableName();
    
    const { data, error } = await supabase
      .from(tableName)
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
    const supabase = getSupabaseClient();
    const tableName = getTableName();
    const normalizedEmail = email.toLowerCase().trim();
    const now = new Date();

    const { data, error } = await supabase
      .from(tableName)
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
