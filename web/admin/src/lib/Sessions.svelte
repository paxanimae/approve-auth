<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "./api";
  import type { Authorization, Me } from "./types";
  import { formatDateTime, formatRelative } from "./format";
  import DurationDialog from "./DurationDialog.svelte";
  import NotesDialog from "./NotesDialog.svelte";
  import ReasonDialog from "./ReasonDialog.svelte";

  let { me }: { me: Me } = $props();

  let authorizations: Authorization[] = $state([]);
  let error: string | null = $state(null);
  let busyId: string | null = $state(null);
  let activeOnly: boolean = $state(true);
  let mineOnly: boolean = $state(false);

  let renewDialogOpen = $state(false);
  let renewTarget: Authorization | null = $state(null);

  let revokeDialogOpen = $state(false);
  let revokeTarget: Authorization | null = $state(null);

  let notesDialogOpen = $state(false);
  let notesTarget: Authorization | null = $state(null);

  function openNotes(a: Authorization) {
    notesTarget = a;
    notesDialogOpen = true;
  }

  async function load() {
    error = null;
    try {
      const result = await api.listAuthorizations(activeOnly, mineOnly);
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

  function stateBadgeClass(state: string): string {
    switch (state) {
      case "active":
        return "badge-success";
      case "awaiting activation":
        return "badge-warning";
      case "expired":
      case "revoked":
        return "badge-danger";
      default:
        return "badge-neutral";
    }
  }

  function openRenew(a: Authorization) {
    renewTarget = a;
    renewDialogOpen = true;
  }

  async function confirmRenew({ days, reason }: { days: number; reason: string }) {
    const a = renewTarget;
    if (!a) return;
    const newExpiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
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

  function openRevoke(a: Authorization) {
    revokeTarget = a;
    revokeDialogOpen = true;
  }

  async function confirmRevoke(reason: string) {
    const a = revokeTarget;
    if (!a) return;
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

  // clearFlag acknowledges a revocation-policy flag_for_review state
  // (internal/revokepolicy) once reviewed -- access was never affected
  // by the flag, so this doesn't restore or revoke anything, it only
  // clears the "needs attention" marker.
  async function clearFlag(a: Authorization) {
    busyId = a.id;
    try {
      await api.clearAuthorizationFlag(a.id);
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }
</script>

<section>
  <div class="section-header">
    <div>
      <h2>Sessions</h2>
      <p class="muted">Sorted by soonest-expiring first.</p>
    </div>
    <div class="toolbar">
      <label class="checkbox-row">
        <input type="checkbox" bind:checked={activeOnly} onchange={load} />
        Active only
      </label>
      <label class="checkbox-row">
        <input type="checkbox" bind:checked={mineOnly} onchange={load} />
        My approvals
      </label>
      <button class="btn" onclick={load}>Refresh</button>
    </div>
  </div>

  {#if error}
    <p role="alert" class="error-text">{error}</p>
  {/if}

  {#if authorizations.length === 0}
    <p class="muted">No sessions match this filter.</p>
  {:else}
    <div class="card table-card">
      <table class="data-table">
        <thead>
          <tr>
            <th>Application</th>
            <th>Label</th>
            <th>State</th>
            <th>Expires</th>
            <th>Last seen</th>
            <th>Approved by</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each authorizations as a (a.id)}
            <tr>
              <td title={a.application_hostname}>{a.application_display_name}</td>
              <td>{a.label ?? "—"}</td>
              <td>
                <span class="badge {stateBadgeClass(sessionState(a))}">{sessionState(a)}</span>
                {#if a.flagged_at}
                  <span class="badge badge-warning" title={a.flagged_reason ?? ""}>flagged</span>
                {/if}
              </td>
              <td title={formatDateTime(a.expires_at)}>{formatRelative(a.expires_at)}</td>
              <td title={formatDateTime(a.last_seen_at)}>{a.last_seen_at ? formatRelative(a.last_seen_at) : "Never seen"}</td>
              <td>{a.approved_by}</td>
              <td class="actions">
                {#if !a.revoked_at}
                  <button class="btn btn-sm" disabled={busyId === a.id} onclick={() => openRenew(a)}>Renew</button>
                  <button class="btn btn-danger btn-sm" disabled={busyId === a.id} onclick={() => openRevoke(a)}>Revoke</button>
                {/if}
                {#if a.flagged_at}
                  <button class="btn btn-sm" disabled={busyId === a.id} onclick={() => clearFlag(a)}>Clear flag</button>
                {/if}
                <button class="btn btn-sm" onclick={() => openNotes(a)}>Notes</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<DurationDialog
  bind:open={renewDialogOpen}
  title="Renew session"
  description={renewTarget ? `Extends the current expiry (${formatDateTime(renewTarget.expires_at)}) by the chosen number of days.` : undefined}
  confirmLabel="Renew"
  reasonRequired
  initialDays={Math.max(1, Math.round(me.default_authorization_duration_seconds / 86400))}
  maxDays={Math.max(1, Math.round(me.max_authorization_duration_seconds / 86400))}
  onConfirm={confirmRenew}
/>

<ReasonDialog
  bind:open={revokeDialogOpen}
  title="Revoke access"
  description={revokeTarget ? `Revoke access for "${revokeTarget.label ?? revokeTarget.id}"? New requests will be denied. This does not close any already-open connection.` : undefined}
  confirmLabel="Revoke"
  danger
  onConfirm={confirmRevoke}
/>

<NotesDialog
  bind:open={notesDialogOpen}
  title="Notes"
  readOnly={me.role !== "administrator" && me.role !== "application_owner"}
  loadNotes={() => api.listAuthorizationNotes(notesTarget!.id).then((r) => r.notes)}
  onAddNote={(body) => api.addAuthorizationNote(notesTarget!.id, { body }).then(() => {})}
/>

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
    gap: var(--space-3);
  }
  .table-card {
    overflow-x: auto;
  }
  .actions {
    display: flex;
    gap: var(--space-2);
    white-space: nowrap;
  }
</style>
