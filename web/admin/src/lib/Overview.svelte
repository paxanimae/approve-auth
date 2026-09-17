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
    <p role="alert" class="error">{error}</p>
  {/if}
  {#if counts}
    <div class="cards">
      <div class="card">
        <span class="value">{counts.pending}</span>
        <span class="label">Pending requests</span>
      </div>
      <div class="card">
        <span class="value">{counts.active}</span>
        <span class="label">Active sessions</span>
      </div>
      <div class="card">
        <span class="value">{counts.expiring_soon}</span>
        <span class="label">Expiring soon</span>
      </div>
      <div class="card">
        <span class="value">{counts.revoked_or_expired_recent}</span>
        <span class="label">Revoked/expired recently</span>
      </div>
    </div>
  {/if}
</section>

<style>
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: var(--space-3);
    margin-top: var(--space-3);
  }
  .card {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    padding: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    background: var(--color-bg-subtle);
  }
  .value {
    font-size: 2rem;
    font-weight: 600;
  }
  .label {
    color: var(--color-text-muted);
  }
  .error {
    color: var(--color-danger);
  }
</style>
