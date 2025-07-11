import { defineConfig } from "tsup";

export default defineConfig({
    entry: [
        "src/index.ts",
        "src/universal.ts",
        "src/nextjs.ts", 
        "src/react.ts",
        "src/utils.ts",
        "src/middleware.ts",
        "src/oauth.ts",
        "src/adapters/index.ts",
        "src/adapters/mongo.ts",
        "src/adapters/supabase.ts",
        "src/adapters/firebase.ts",
        "src/providers/google.ts",
        "src/providers/github.ts"
    ],
    format: ["cjs", "esm"],
    dts: true,
    sourcemap: false, // Remove source maps to reduce size
    clean: true,
    outDir: "dist",
    target: "node18",
    splitting: false,
    minify: true, // Enable minification
    external: [
        // Core peer dependencies
        "mongodb",
        "@supabase/supabase-js", 
        "firebase",
        "firebase-admin",
        "firebase/app",
        "firebase/firestore",
        "axios",
        "dotenv",
        "express",
        // Next.js dependencies (optional peer dependencies)
        "next",
        "next/server",
        "next/headers",
        "next/navigation",
        // React dependencies (optional peer dependencies)
        "react",
        "react-dom"
    ],
    outExtension({ format }) {
        return {
            js: format === "cjs" ? ".cjs" : ".mjs"
        };
    },
});
