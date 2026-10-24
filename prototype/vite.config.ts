/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "./",
  build: { rollupOptions: { input: { main: "index.html", ux: "ux.html" } } },
  server: { port: 5199, strictPort: true },
  test: { globals: true, include: ["test/**/*.test.ts"] },
});
