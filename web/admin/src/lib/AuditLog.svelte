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
  <h2>Audit log</h2>
  <div class="toolbar">
    <button onclick={load}>Refresh</button>
    <a href="/api/v1/audit-events/export">Export CSV</a>
  </div>

  {#if error}
    <p role="alert" class="error">{error}</p>
  {/if}

  <table>
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
          <td>{e.action}</td>
          <td>{e.outcome}</td>
          <td>{e.reason ?? "—"}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>

<style>
  .toolbar {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th, td {
    text-align: left;
    padding: var(--space-2);
    border-bottom: 1px solid var(--color-border);
  }
  .error {
    color: var(--color-danger);
  }
</style>
