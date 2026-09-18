<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "./api";
  import type { Overview } from "./types";

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
      <div class="card stat">
        <span class="value">{counts.pending}</span>
        <span class="label">Pending requests</span>
      </div>
      <div class="card stat">
        <span class="value">{counts.active}</span>
        <span class="label">Active sessions</span>
      </div>
      <div class="card stat">
        <span class="value">{counts.expiring_soon}</span>
        <span class="label">Expiring soon</span>
      </div>
      <div class="card stat">
        <span class="value">{counts.revoked_or_expired_recent}</span>
        <span class="label">Revoked/expired recently</span>
      </div>
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
</style>
