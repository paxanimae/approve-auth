// Dark is the product default (not a prefers-color-scheme fallback) --
// light is only ever active because a person on this browser explicitly
// chose it. The choice is a per-browser display preference, not
// anything the server needs to know or that other viewers should see,
// so it lives in localStorage only.
const STORAGE_KEY = "approve-admin-theme";

export type Theme = "dark" | "light";

function safeGet(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function safeSet(value: string): void {
  try {
    localStorage.setItem(STORAGE_KEY, value);
  } catch {
    // Best-effort only -- a private window or blocked storage just
    // means the choice doesn't survive a reload.
  }
}

export function currentTheme(): Theme {
  return safeGet() === "light" ? "light" : "dark";
}

export function applyTheme(theme: Theme): void {
  if (theme === "light") {
    document.documentElement.setAttribute("data-theme", "light");
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
}

export function initTheme(): Theme {
  const theme = currentTheme();
  applyTheme(theme);
  return theme;
}

export function setTheme(theme: Theme): void {
  safeSet(theme);
  applyTheme(theme);
}
