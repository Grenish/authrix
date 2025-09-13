import { defineConfig } from "tsup";

export default defineConfig({
    entry: [
    "src/index.ts",
    "src/core.barrel.ts",
    "src/security.ts",
    "src/advanced.ts",
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
    sourcemap: false,
    clean: true,
    outDir: "dist",
    target: "node18",
    splitting: true,
    minify: true,
    treeshake: true,
    external: [
        "mongodb",
        "@supabase/supabase-js", 
        "firebase",
        "firebase-admin",
        "firebase/app",
        "firebase/firestore",
        "axios",
        "dotenv",
        "express",
        "next",
        "next/server",
        "next/headers",
        "next/navigation",
        "react",
    "react-dom",
    "@prisma/client"
    ],
    esbuildOptions(options) {
        options.drop = ['console', 'debugger'];
        options.legalComments = 'none';
        options.treeShaking = true;
        options.mangleProps = /^_/;
    },
    outExtension({ format }) {
        return {
            js: format === "cjs" ? ".cjs" : ".mjs"
        };
    },
});
