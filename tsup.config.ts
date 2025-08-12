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
        "src/sso.ts",
        "src/forgotPassword.ts",
        "src/adapters/index.ts",
        "src/adapters/mongo.ts",
        "src/adapters/postgresql.ts",
    "src/adapters/prisma.ts",
        "src/providers/google.ts",
        "src/providers/github.ts"
    ],
    format: ["cjs", "esm"],
    dts: true,
    sourcemap: false, // Remove source maps to reduce size
    clean: true,
    outDir: "dist",
    target: "node18",
    // Re-enable code splitting so consumers only load what they import; we'll reduce file count via other means
    splitting: true,
    minify: true, // Enable minification
    treeshake: true, // Enable tree-shaking
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
    "react-dom",
    "@prisma/client"
    ],
    esbuildOptions(options) {
        // Enable advanced minification
        options.drop = ['console', 'debugger'];
        options.legalComments = 'none';
        options.treeShaking = true;
        // Enable property mangling for better compression
        options.mangleProps = /^_/;
    },
    outExtension({ format }) {
        return {
            js: format === "cjs" ? ".cjs" : ".mjs"
        };
    },
});
