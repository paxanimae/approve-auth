<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "./api";
  import type { Overview } from "./types";

  // onNavigate, when supplied, turns each stat tile into a shortcut to
  // the view that actually explains that number -- pending requests
  // and the other three (all authorization-state counts) route to
  // different views (App.svelte's own ViewName), so this takes a
  // string rather than a fixed literal.
  let { onNavigate }: { onNavigate?: (view: "requests" | "sessions") => void } = $props();

  let counts: Overview | null = $state(null);
  let error: string | null = $state(null);

  async function load() {
    error = null;
    try {
      counts = await api.overview();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  onMount(load);
</script>

<section>
  <h2>Overview</h2>
  {#if error}
    <p role="alert" class="error-text">{error}</p>
  {/if}
  {#if counts}
    <div class="cards">
      <button class="card stat stat-link" onclick={() => onNavigate?.("requests")}>
        <span class="value">{counts.pending}</span>
        <span class="label">Pending requests</span>
      </button>
      <button class="card stat stat-link" onclick={() => onNavigate?.("sessions")}>
        <span class="value">{counts.active}</span>
        <span class="label">Active sessions</span>
      </button>
      <button class="card stat stat-link" onclick={() => onNavigate?.("sessions")}>
        <span class="value">{counts.expiring_soon}</span>
        <span class="label">Expiring soon</span>
      </button>
      <button class="card stat stat-link" onclick={() => onNavigate?.("sessions")}>
        <span class="value">{counts.revoked_or_expired_recent}</span>
        <span class="label">Revoked/expired recently</span>
      </button>
    </div>
  {/if}
</section>

<style>
  h2 {
    margin-bottom: var(--space-4);
  }
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: var(--space-3);
  }
  .stat {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    padding: var(--space-4);
  }
  .value {
    font-size: var(--font-size-3xl);
    font-weight: 700;
    color: var(--color-accent);
  }
  .label {
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }
  .stat-link {
    font: inherit;
    text-align: left;
    border: 1px solid var(--color-border);
    cursor: pointer;
    transition: background-color 0.12s ease, border-color 0.12s ease, transform 0.12s ease;
  }
  .stat-link:hover {
    background: var(--color-surface-hover);
    border-color: var(--color-border-strong);
    transform: translateY(-1px);
  }
  .stat-link:focus-visible {
    outline: 2px solid var(--color-accent);
    outline-offset: 2px;
  }
</style>
