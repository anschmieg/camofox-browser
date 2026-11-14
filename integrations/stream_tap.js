/**
 * Stealth In-Page SSE HTTP Stream Tap for ChatGPT conversations.
 * Uses a Proxy wrapper on fetch with body.tee() and preserves native Function.prototype.toString.
 * Intercepts raw HTTP SSE response chunks directly from the network layer.
 *
 * Employs non-enumerable Symbol state storage to prevent bot scanners from detecting
 * global variables on the window object.
 */
(() => {
  const TAP_KEY = Symbol.for('__camofox_tap__');
  if (window[TAP_KEY]) return;

  const tapState = {
    installed: true,
    generation: 0,
    chunks: [],
    byteCount: 0,
    activeReader: null,
    done: false,
    error: null,
    discovered_models: []
  };

  Object.defineProperty(window, TAP_KEY, {
    value: tapState,
    enumerable: false,
    configurable: false,
    writable: false
  });

  const originalFetch = window.fetch;
  const originalToString = Function.prototype.toString;

  const fetchHandler = {
    apply(target, thisArg, args) {
      let url = '';
      try {
        url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
      } catch (_) {}

      const init = args[1] || {};
      const method = (init.method ? String(init.method) : (args[0] && args[0].method ? String(args[0].method) : 'GET')).toUpperCase();
      const isPost = method === 'POST';

      const isConversationStream = isPost && typeof url === 'string' && (
        url.endsWith('/backend-api/conversation') ||
        url.includes('/backend-api/conversation?') ||
        url.endsWith('/conversation') ||
        url.includes('/conversation?')
      ) && !url.includes('/conversations') && !url.includes('/lat/');

      if (isConversationStream) {
        if (tapState.activeReader) {
          try { tapState.activeReader.cancel(); } catch (_) {}
          tapState.activeReader = null;
        }
        const genId = ++tapState.generation;
        tapState.chunks = [];
        tapState.byteCount = 0;
        tapState.done = false;
        tapState.error = null;

        return Reflect.apply(target, thisArg, args).then(res => {
          if (!res || !res.ok) {
            if (genId === tapState.generation) {
              tapState.error = `HTTP ${res ? res.status : 'error'}: ${res ? res.statusText : ''}`;
              tapState.done = true;
            }
            return res;
          }

          if (!res.body) {
            if (genId === tapState.generation) {
              tapState.done = true;
            }
            return res;
          }

          try {
            const [appStream, tapStream] = res.body.tee();
            const reader = tapStream.getReader();
            if (genId === tapState.generation) {
              tapState.activeReader = reader;
            }
            const decoder = new TextDecoder();
            const MAX_BYTES = 25 * 1024 * 1024; // 25MB safety ceiling

            (async () => {
              try {
                while (true) {
                  const { done, value } = await reader.read();
                  if (done || genId !== tapState.generation) {
                    try { reader.cancel().catch(() => {}); } catch (_) {}
                    break;
                  }
                  if (value && genId === tapState.generation) {
                    tapState.byteCount += value.byteLength || value.length || 0;
                    if (tapState.byteCount > MAX_BYTES) {
                      tapState.error = 'Captured stream exceeded 25MB limit';
                      try { reader.cancel().catch(() => {}); } catch (_) {}
                      break;
                    }
                    const textChunk = decoder.decode(value, { stream: true });
                    if (tapState.chunks.length >= 10000) {
                      tapState.error = 'Captured stream exceeded chunk limit (10000 chunks)';
                      try { reader.cancel().catch(() => {}); } catch (_) {}
                      break;
                    }
                    tapState.chunks.push(textChunk);
                  }
                }
                if (genId === tapState.generation && !tapState.error) {
                  const trailing = decoder.decode();
                  if (trailing) {
                    if (tapState.chunks.length >= 10000) {
                      tapState.error = 'Captured stream exceeded chunk limit (10000 chunks)';
                    } else {
                      tapState.chunks.push(trailing);
                    }
                  }
                }
              } catch (err) {
                if (genId === tapState.generation) {
                  tapState.error = String(err);
                }
              } finally {
                if (genId === tapState.generation) {
                  if (tapState.activeReader === reader) {
                    tapState.activeReader = null;
                  }
                  tapState.done = true;
                }
                try { reader.cancel().catch(() => {}); } catch (_) {}
              }
            })();

            const newRes = new Response(appStream, res);
            try {
              if (res.url !== undefined) Object.defineProperty(newRes, 'url', { value: res.url, configurable: true });
              if (res.redirected !== undefined) Object.defineProperty(newRes, 'redirected', { value: res.redirected, configurable: true });
              if (res.type !== undefined) Object.defineProperty(newRes, 'type', { value: res.type, configurable: true });
              return newRes;
            } catch (_) {
              return new Proxy(newRes, {
                get(t, p) {
                  if (p === 'url') return res.url;
                  if (p === 'redirected') return res.redirected;
                  if (p === 'type') return res.type;
                  const val = Reflect.get(t, p, t);
                  return typeof val === 'function' ? val.bind(t) : val;
                }
              });
            }
          } catch (e) {
            // Fallback if tee not supported
            return res;
          }
        }).catch(err => {
          if (genId === tapState.generation) {
            tapState.error = String(err);
            tapState.done = true;
          }
          throw err;
        });
      }

      if (typeof url === 'string' && url.includes('/backend-api/models')) {
        return Reflect.apply(target, thisArg, args).then(res => {
          if (res && res.ok) {
            try {
              res.clone().json().then(data => {
                if (data && Array.isArray(data.models)) {
                  tapState.discovered_models = data.models.map(m => m.slug);
                }
              }).catch(() => {});
            } catch (_) {}
          }
          return res;
        });
      }
      return Reflect.apply(target, thisArg, args);
    }
  };

  const proxiedFetch = new Proxy(originalFetch, fetchHandler);

  const originalGetOwnPropertySymbols = Object.getOwnPropertySymbols;
  const originalOwnKeys = Reflect.ownKeys;

  // Mask internal tap Symbol from anti-bot reflection probes (window only)
  const proxiedGetOwnPropertySymbols = new Proxy(originalGetOwnPropertySymbols, {
    apply(target, thisArg, args) {
      const syms = Reflect.apply(target, thisArg, args);
      if (args && args[0] !== window) return syms;
      return syms.filter(s => s !== TAP_KEY);
    }
  });

  const proxiedOwnKeys = new Proxy(originalOwnKeys, {
    apply(target, thisArg, args) {
      const keys = Reflect.apply(target, thisArg, args);
      if (args && args[0] !== window) return keys;
      return keys.filter(k => k !== TAP_KEY);
    }
  });

  Object.getOwnPropertySymbols = proxiedGetOwnPropertySymbols;
  Reflect.ownKeys = proxiedOwnKeys;

  // Preserve native Function.prototype.toString inspection and pass recursive check
  const proxiedToString = new Proxy(originalToString, {
    apply(target, thisArg, args) {
      if (thisArg === proxiedFetch) {
        return 'function fetch() {\n    [native code]\n}';
      }
      if (thisArg === proxiedGetOwnPropertySymbols) {
        return 'function getOwnPropertySymbols() {\n    [native code]\n}';
      }
      if (thisArg === proxiedOwnKeys) {
        return 'function ownKeys() {\n    [native code]\n}';
      }
      if (thisArg === proxiedToString) {
        return 'function toString() {\n    [native code]\n}';
      }
      return Reflect.apply(target, thisArg, args);
    }
  });

  Function.prototype.toString = proxiedToString;

  Object.defineProperty(window, 'fetch', {
    value: proxiedFetch,
    writable: true,
    enumerable: true,
    configurable: true
  });
})();
