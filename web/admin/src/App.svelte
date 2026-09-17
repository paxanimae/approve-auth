<script lang="ts">
  import "./lib/tokens.css";
  import { onMount } from "svelte";
  import { api, setCsrfToken } from "./lib/api";
  import type { Me } from "./lib/types";
  import Overview from "./lib/Overview.svelte";
  import Requests from "./lib/Requests.svelte";
  import Sessions from "./lib/Sessions.svelte";
  import Applications from "./lib/Applications.svelte";
  import AuditLog from "./lib/AuditLog.svelte";

  type View = "overview" | "requests" | "sessions" | "applications" | "audit";

  let me: Me | null = $state(null);
  let checkingSession = $state(true);
  let view: View = $state("overview");

  onMount(async () => {
    try {
      const identity = await api.me();
      me = identity;
      setCsrfToken(identity.csrf_token);
    } catch {
      me = null;
    } finally {
      checkingSession = false;
    }
  });

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

<main>
  {#if checkingSession}
    <p>Loading…</p>
  {:else if !me}
    <div class="login">
      <h1>Manual Approval Admin Console</h1>
      <p>Sign in with your organizational identity provider to continue.</p>
      <a class="button" href="/auth/login?return_to=/">Log in</a>
    </div>
  {:else}
    <header>
      <h1>Manual Approval Admin Console</h1>
      <div class="identity">
        <span>{me.display_name || me.subject} ({me.role})</span>
        <button onclick={logout}>Log out</button>
      </div>
    </header>

    <nav>
      <button class:active={view === "overview"} onclick={() => (view = "overview")}>Overview</button>
      <button class:active={view === "requests"} onclick={() => (view = "requests")}>Requests</button>
      <button class:active={view === "sessions"} onclick={() => (view = "sessions")}>Sessions</button>
      <button class:active={view === "applications"} onclick={() => (view = "applications")}>Applications</button>
      <button class:active={view === "audit"} onclick={() => (view = "audit")}>Audit log</button>
    </nav>

    <div class="content">
      {#if view === "overview"}
        <Overview />
      {:else if view === "requests"}
        <Requests />
      {:else if view === "sessions"}
        <Sessions />
      {:else if view === "applications"}
        <Applications />
      {:else if view === "audit"}
        <AuditLog />
      {/if}
    </div>
  {/if}
</main>

<style>
  main {
    font-family: var(--font-sans);
    color: var(--color-text);
    background: var(--color-bg);
    min-height: 100vh;
    padding: var(--space-4);
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--space-3);
  }
  .identity {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    color: var(--color-text-muted);
  }
  nav {
    display: flex;
    gap: var(--space-2);
    border-bottom: 1px solid var(--color-border);
    margin-bottom: var(--space-4);
    padding-bottom: var(--space-2);
  }
  nav button {
    background: none;
    border: none;
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius);
    cursor: pointer;
    color: var(--color-text);
  }
  nav button.active {
    background: var(--color-accent);
    color: white;
  }
  .login {
    max-width: 32rem;
    margin: 4rem auto;
    text-align: center;
  }
  .button {
    display: inline-block;
    margin-top: var(--space-3);
    padding: var(--space-2) var(--space-4);
    background: var(--color-accent);
    color: white;
    border-radius: var(--radius);
    text-decoration: none;
  }
  button {
    font: inherit;
  }
</style>
