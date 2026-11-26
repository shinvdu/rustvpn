Vendored subset of `@tauri-apps/api` 2.12.5 (MIT OR Apache-2.0).

Only `core.js`, `event.js` and the tslib helper are included. The sibling
`ui/tauri-bridge.js` is the esbuild IIFE bundle of those modules, loaded as a
classic script so startup ordering is deterministic. They talk to the
`window.__TAURI_INTERNALS__` bridge that Tauri injects regardless of
`withGlobalTauri`, so the GUI can keep a zero-build static frontend without
exposing the full global API.
