/**
 * Configure Vite's React integration for local development and production builds.
 *
 * @example
 * npm run build
 */
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
});
