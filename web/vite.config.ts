import { defineConfig } from "vite";

export default defineConfig({
  // No data: URLs: the CSP only allows assets from 'self'.
  build: { target: "es2022", outDir: "../crates/hexcrypt/dist", emptyOutDir: true, assetsInlineLimit: 0 },
  server: {
    proxy: { "/api": "http://127.0.0.1:8080" },
  },
});
