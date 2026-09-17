<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "./api";
  import type { ApprovalRequest } from "./types";
  import { formatDateTime, formatRelative } from "./format";

  let requests: ApprovalRequest[] = $state([]);
  let error: string | null = $state(null);
  let busyId: string | null = $state(null);
  let statusFilter: string = $state("pending");

  async function load() {
    error = null;
    try {
      const result = await api.listRequests(statusFilter || undefined);
      requests = result.requests;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  onMount(load);

  async function approve(r: ApprovalRequest) {
    const days = prompt("Grant access for how many days?", "30");
    if (days === null) return;
    const n = Number(days);
    if (!Number.isFinite(n) || n <= 0) {
      alert("Enter a positive number of days.");
      return;
    }
    const expiresAt = new Date(Date.now() + n * 24 * 60 * 60 * 1000).toISOString();
    busyId = r.id;
    try {
      await api.approveRequest(r.id, { version: r.version, expires_at: expiresAt, label: r.label });
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }

  async function deny(r: ApprovalRequest) {
    const reason = prompt("Reason for denial (recorded privately):");
    if (reason === null || reason.trim() === "") return;
    busyId = r.id;
    try {
      await api.denyRequest(r.id, { version: r.version, reason });
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }
</script>

<section>
  <h2>Requests</h2>
  <div class="toolbar">
    <label>
      Status
      <select bind:value={statusFilter} onchange={load}>
        <option value="pending">Pending</option>
        <option value="approved">Approved (awaiting claim)</option>
        <option value="claimed">Claimed</option>
        <option value="denied">Denied</option>
        <option value="">All</option>
      </select>
    </label>
    <button onclick={load}>Refresh</button>
  </div>

  {#if error}
    <p role="alert" class="error">{error}</p>
  {/if}

  {#if requests.length === 0}
    <p class="muted">No requests in this state.</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Label</th>
          <th>Verification code</th>
          <th>Status</th>
          <th>Requested</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each requests as r (r.id)}
          <tr>
            <td>{r.label ?? "—"}</td>
            <td class="code">{r.verification_code}</td>
            <td>{r.status}</td>
            <td title={formatDateTime(r.requested_at)}>{formatRelative(r.requested_at)}</td>
            <td>
              {#if r.status === "pending"}
                <button disabled={busyId === r.id} onclick={() => approve(r)}>Approve</button>
                <button disabled={busyId === r.id} class="danger" onclick={() => deny(r)}>Deny</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
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
  .code {
    font-family: monospace;
  }
  .muted {
    color: var(--color-text-muted);
  }
  .error {
    color: var(--color-danger);
  }
  button.danger {
    color: var(--color-danger);
  }
</style>
