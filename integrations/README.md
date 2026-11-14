# Integrations

`STREAM_TAP_PATH` (env, optional): path to a JS file injected into every
browser context at creation. The chatgpt2api bridge injects its stream tap
per-tab after navigation (via /tabs/{id}/evaluate), so this is optional.

Paired copies (e.g. the chatgpt2api fork's stream_tap.js) are NOT stored in
this repo — the fork is private. Mount or bake one at deploy time if the
init-script injection is needed.
