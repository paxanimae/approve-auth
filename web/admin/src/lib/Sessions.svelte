<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "./api";
  import type { Authorization } from "./types";
  import { formatDateTime, formatRelative } from "./format";

  let authorizations: Authorization[] = $state([]);
  let error: string | null = $state(null);
  let busyId: string | null = $state(null);
  let activeOnly: boolean = $state(true);

  async function load() {
    error = null;
    try {
      const result = await api.listAuthorizations(activeOnly);
      authorizations = result.authorizations;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  onMount(load);

  function sessionState(a: Authorization): string {
    if (a.revoked_at) return "revoked";
    if (!a.activated_at) return "awaiting activation";
    if (new Date(a.expires_at).getTime() <= Date.now()) return "expired";
    return "active";
  }

  async function renew(a: Authorization) {
    const days = prompt("Extend by how many days? (added to the current expiry)", "30");
    if (days === null) return;
    const n = Number(days);
    if (!Number.isFinite(n) || n <= 0) {
      alert("Enter a positive number of days.");
      return;
    }
    const reason = prompt("Reason (recorded in the audit log):") ?? "";
    const newExpiresAt = new Date(new Date(a.expires_at).getTime() + n * 24 * 60 * 60 * 1000).toISOString();
    busyId = a.id;
    try {
      await api.renewAuthorization(a.id, { version: a.version, new_expires_at: newExpiresAt, reason });
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }

  async function revoke(a: Authorization) {
    const reason = prompt("Reason for revocation (recorded in the audit log):");
    if (reason === null || reason.trim() === "") return;
    if (!confirm(`Revoke access for "${a.label ?? a.id}"? New requests will be denied. This does not close any already-open connection.`)) return;
    busyId = a.id;
    try {
      await api.revokeAuthorization(a.id, { version: a.version, reason });
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }
</script>

<section>
  <h2>Sessions</h2>
  <p class="muted">Sorted by soonest-expiring first.</p>
  <div class="toolbar">
    <label>
      <input type="checkbox" bind:checked={activeOnly} onchange={load} />
      Active only (hide revoked/expired)
    </label>
    <button onclick={load}>Refresh</button>
  </div>

  {#if error}
    <p role="alert" class="error">{error}</p>
  {/if}

  {#if authorizations.length === 0}
    <p class="muted">No sessions match this filter.</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Label</th>
          <th>State</th>
          <th>Expires</th>
          <th>Last seen</th>
          <th>Approved by</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each authorizations as a (a.id)}
          <tr>
            <td>{a.label ?? "—"}</td>
            <td>{sessionState(a)}</td>
            <td title={formatDateTime(a.expires_at)}>{formatRelative(a.expires_at)}</td>
            <td title={formatDateTime(a.last_seen_at)}>{a.last_seen_at ? formatRelative(a.last_seen_at) : "Never seen"}</td>
            <td>{a.approved_by}</td>
            <td>
              {#if !a.revoked_at}
                <button disabled={busyId === a.id} onclick={() => renew(a)}>Renew</button>
                <button disabled={busyId === a.id} class="danger" onclick={() => revoke(a)}>Revoke</button>
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
