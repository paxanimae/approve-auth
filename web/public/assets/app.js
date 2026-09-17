// Progressive enhancement only. Every page this file touches must keep
// working with JavaScript disabled (spec section 2/5) -- a manual Refresh
// button and a plain HTML <meta refresh> fallback are how those pages
// re-check state without this file. Milestone 2 adds the actual polling
// behavior described in spec section 5, step 5 (5s+jitter, backing off to
// 60s, pausing in hidden tabs).
