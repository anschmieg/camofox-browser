# ChatGPT stream tap (paired copy)

`stream_tap.js` is maintained in the chatgpt2api fork
(`services/browser_bridge/stream_tap.js`) and copied here at release time.
The camofox server injects it into every browser context at creation
(`STREAM_TAP_PATH` env, set in the Coolify app to this file).

When updating the fork's tap, copy it here and redeploy camofox — the canary
(`services.browser_bridge.canary`) catches drift.
