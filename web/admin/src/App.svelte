<script lang="ts">
  import "./lib/tokens.css";
  import { onMount } from "svelte";
  import { api, setCsrfToken } from "./lib/api";
  import type { Me } from "./lib/types";
  import { initTheme, setTheme, type Theme } from "./lib/theme";
  import Overview from "./lib/Overview.svelte";
  import Requests from "./lib/Requests.svelte";
  import Sessions from "./lib/Sessions.svelte";
  import Applications from "./lib/Applications.svelte";
  import AuditLog from "./lib/AuditLog.svelte";
  import Settings from "./lib/Settings.svelte";

  type ViewName = "overview" | "requests" | "sessions" | "applications" | "audit" | "settings";
  const allViews: { id: ViewName; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "requests", label: "Requests" },
    { id: "sessions", label: "Sessions" },
    { id: "applications", label: "Applications" },
    { id: "audit", label: "Audit log" },
    { id: "settings", label: "Settings" },
  ];
  // An ApplicationOwner "cannot control anything else" beyond their own
  // application's requests/sessions (spec) -- overview, applications
  // management, and the audit log all 403 for that role server-side, so
  // there's no point showing nav entries that only lead to an error.
  let views: { id: ViewName; label: string }[] = $state(allViews);

  let me: Me | null = $state(null);
  let checkingSession = $state(true);
  let view: ViewName = $state("overview");
  let theme: Theme = $state("dark");
  let navOpen = $state(false);

  onMount(async () => {
    theme = initTheme();
    try {
      const identity = await api.me();
      me = identity;
      setCsrfToken(identity.csrf_token);
      if (identity.role === "application_owner") {
        views = allViews.filter((v) => v.id === "requests" || v.id === "sessions");
        view = "requests";
      }
    } catch {
      me = null;
    } finally {
      checkingSession = false;
    }
  });

  function toggleTheme() {
    theme = theme === "dark" ? "light" : "dark";
    setTheme(theme);
  }

  function selectView(v: ViewName) {
    view = v;
    navOpen = false;
  }

  async function logout() {
    try {
      await api.logout();
    } catch {
      // Best-effort: the cookie is cleared server-side either way once
      // the session is found, and a session that's already gone just
      // means there was nothing to log out of.
    }
    me = null;
  }
</script>

{#snippet logoMark(size: number)}
  <img src="/favicon.svg" width={size} height={size} alt="" class="logo-mark" />
{/snippet}

{#snippet themeToggleIcon()}
  {#if theme === "dark"}
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></svg>
  {:else}
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" /></svg>
  {/if}
{/snippet}

{#if checkingSession}
  <div class="boot">Loading…</div>
{:else if !me}
  <div class="login-screen">
    <div class="login-card card">
      {@render logoMark(40)}
      <h1>Approve</h1>
      <p class="muted">Sign in with your organizational identity provider to continue.</p>
      <a class="btn btn-primary" href="/auth/login?return_to=/">Log in</a>
    </div>
  </div>
{:else}
  <div class="shell" class:nav-open={navOpen}>
    <div class="scrim" onclick={() => (navOpen = false)} role="presentation"></div>

    <aside class="sidebar">
      <div class="brand">
        {@render logoMark(28)}
        <span class="wordmark">Approve</span>
      </div>

      <nav>
        {#each views as v (v.id)}
          <button class:active={view === v.id} onclick={() => selectView(v.id)}>{v.label}</button>
        {/each}
      </nav>

      <div class="sidebar-footer">
        <button class="theme-toggle" onclick={toggleTheme} title="Toggle theme" aria-label="Toggle theme">
          {@render themeToggleIcon()}
          {theme === "dark" ? "Dark" : "Light"}
        </button>
        <div class="identity">
          <div class="identity-name">{me.display_name || me.subject}</div>
          <div class="identity-role muted">{me.role}</div>
        </div>
        <button class="btn btn-ghost btn-sm" onclick={logout}>Log out</button>
        <div class="build-info muted">
          {#if me.instance_name}{me.instance_name} &middot; {/if}v{me.version}
        </div>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <button class="hamburger" onclick={() => (navOpen = !navOpen)} aria-label="Toggle navigation">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h16" /></svg>
        </button>
        <h2>{views.find((v) => v.id === view)?.label}</h2>
      </header>

      <div class="content">
        {#if view === "overview"}
          <Overview onNavigate={selectView} />
        {:else if view === "requests"}
          <Requests {me} />
        {:else if view === "sessions"}
          <Sessions {me} />
        {:else if view === "applications"}
          <Applications />
        {:else if view === "audit"}
          <AuditLog />
        {:else if view === "settings"}
          <Settings {me} />
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  :global(.logo-mark) {
    display: block;
    border-radius: 6px;
  }

  .boot {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--color-text-muted);
  }

  .login-screen {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--space-4);
    background: radial-gradient(circle at 50% 0%, var(--color-accent-soft), transparent 60%);
  }

  .login-card {
    width: min(24rem, 100%);
    padding: var(--space-5);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-2);
    text-align: center;
  }

  .login-card h1 {
    font-size: var(--font-size-2xl);
    margin-top: var(--space-2);
  }

  .login-card .btn {
    margin-top: var(--space-3);
    width: 100%;
  }

  .shell {
    display: flex;
    min-height: 100vh;
  }

  .scrim {
    display: none;
  }

  .sidebar {
    width: var(--sidebar-width);
    flex-shrink: 0;
    background: var(--color-bg-elevated);
    border-right: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    padding: var(--space-4) var(--space-3);
    gap: var(--space-4);
  }

  .brand {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: 0 var(--space-2);
  }

  .wordmark {
    font-size: var(--font-size-lg);
    font-weight: 700;
    letter-spacing: -0.01em;
  }

  nav {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  nav button {
    text-align: left;
    font: inherit;
    font-size: var(--font-size-sm);
    font-weight: 500;
    color: var(--color-text-muted);
    background: none;
    border: none;
    padding: 0.55rem var(--space-2);
    border-radius: var(--radius-sm);
    cursor: pointer;
  }

  nav button:hover {
    background: var(--color-surface-hover);
    color: var(--color-text);
  }

  nav button.active {
    background: var(--color-accent-soft);
    color: var(--color-accent);
  }

  .sidebar-footer {
    margin-top: auto;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    padding-top: var(--space-3);
    border-top: 1px solid var(--color-border);
  }

  .theme-toggle {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font: inherit;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    background: none;
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-sm);
    padding: 0.4rem var(--space-2);
    cursor: pointer;
  }

  .theme-toggle:hover {
    color: var(--color-text);
    background: var(--color-surface-hover);
  }

  .identity-name {
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  .identity-role {
    font-size: var(--font-size-xs);
    text-transform: capitalize;
  }

  .build-info {
    font-size: var(--font-size-xs);
    text-align: center;
  }

  .main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }

  .topbar {
    display: none;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
    border-bottom: 1px solid var(--color-border);
    background: var(--color-bg-elevated);
  }

  .hamburger {
    background: none;
    border: none;
    color: var(--color-text);
    cursor: pointer;
    padding: var(--space-1);
    display: flex;
  }

  .content {
    flex: 1;
    padding: var(--space-5);
  }

  @media (max-width: 860px) {
    .sidebar {
      position: fixed;
      inset: 0 auto 0 0;
      z-index: 20;
      transform: translateX(-100%);
      transition: transform 0.18s ease;
      box-shadow: var(--shadow-popover);
    }

    .shell.nav-open .sidebar {
      transform: translateX(0);
    }

    .shell.nav-open .scrim {
      display: block;
      position: fixed;
      inset: 0;
      background: rgb(4 5 10 / 0.5);
      z-index: 10;
    }

    .topbar {
      display: flex;
    }

    .content {
      padding: var(--space-4);
    }
  }
</style>
