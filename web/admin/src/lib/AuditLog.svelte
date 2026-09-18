<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "./api";
  import type { AuditEvent } from "./types";
  import { formatDateTime } from "./format";

  let events: AuditEvent[] = $state([]);
  let error: string | null = $state(null);

  async function load() {
    error = null;
    try {
      const result = await api.listAuditEvents();
      events = result.audit_events;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  onMount(load);
</script>

<section>
  <div class="section-header">
    <h2>Audit log</h2>
    <div class="toolbar">
      <a class="btn" href="/api/v1/audit-events/export">Export CSV</a>
      <button class="btn" onclick={load}>Refresh</button>
    </div>
  </div>

  {#if error}
    <p role="alert" class="error-text">{error}</p>
  {/if}

  <div class="card table-card">
    <table class="data-table">
      <thead>
        <tr>
          <th>When</th>
          <th>Actor</th>
          <th>Action</th>
          <th>Outcome</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody>
        {#each events as e (e.id)}
          <tr>
            <td>{formatDateTime(e.occurred_at)}</td>
            <td>{e.actor_subject ?? e.actor_type}</td>
            <td class="mono">{e.action}</td>
            <td><span class="badge {e.outcome === 'success' ? 'badge-success' : 'badge-danger'}">{e.outcome}</span></td>
            <td>{e.reason ?? "—"}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<style>
  .section-header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }
  .table-card {
    overflow-x: auto;
  }
  .mono {
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
  }
</style>
