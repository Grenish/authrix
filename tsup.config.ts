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
    outExtension({ format }) {
        return {
            js: format === "cjs" ? ".cjs" : ".mjs"
        };
    },
});
