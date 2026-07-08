// Build script — produces dual ESM/CJS output as required by SPEC §6.
// Not minified: consumers typically re-bundle and minify with their own toolchain.

import { build } from "esbuild";

const shared = {
  entryPoints: ["src/index.ts"],
  bundle: true,
  platform: "browser",
  target: ["es2020"],
  sourcemap: true,
  minify: false,
  logLevel: "info",
};

await Promise.all([
  build({ ...shared, format: "esm", outfile: "dist/index.js" }),
  build({ ...shared, format: "cjs", outfile: "dist/index.cjs" }),
]);

console.log("[esbuild] built dist/index.js (ESM) and dist/index.cjs (CJS)");
