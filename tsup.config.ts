import { defineConfig } from "tsup";

export default defineConfig({
    entry: ["src/index.ts"],
    format: ["cjs", "esm"],
    dts: true,
    sourcemap: true,
    clean: true,
    outDir: "dist",
    target: "node18",
    splitting: false,
    external: [
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
