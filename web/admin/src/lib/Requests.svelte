<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError } from "./api";
  import type { ApprovalRequest, Me } from "./types";
  import { formatDateTime, formatRelative } from "./format";
  import DurationDialog from "./DurationDialog.svelte";
  import NotesDialog from "./NotesDialog.svelte";
  import ReasonDialog from "./ReasonDialog.svelte";

  // openRequestId: set when the console was opened via the waiting
  // page's approve-by-QR deep link (App.svelte reads ?open_request=
  // from the URL) -- once loaded, that specific request's approve
  // dialog opens automatically instead of requiring a scroll/search
  // through the table. onHandledDeepLink tells App.svelte the id has
  // been acted on (found and opened, or reported as not-found/already-
  // resolved) so it can clear its own state -- this component gets
  // destroyed and recreated every time the admin navigates away from
  // and back to this tab, so without that, switching back later in the
  // same session would re-trigger the same auto-open again.
  let { me, openRequestId, onHandledDeepLink }: { me: Me; openRequestId?: string; onHandledDeepLink?: () => void } = $props();

  let requests: ApprovalRequest[] = $state([]);
  let error: string | null = $state(null);
  let busyId: string | null = $state(null);
  let statusFilter: string = $state("pending");
  let deepLinkNotice: string | null = $state(null);

  let approveDialogOpen = $state(false);
  let approveTarget: ApprovalRequest | null = $state(null);

  let denyDialogOpen = $state(false);
  let denyTarget: ApprovalRequest | null = $state(null);

  let notesDialogOpen = $state(false);
  let notesTarget: ApprovalRequest | null = $state(null);

  function openNotes(r: ApprovalRequest) {
    notesTarget = r;
    notesDialogOpen = true;
  }

  async function load() {
    error = null;
    try {
      const result = await api.listRequests(statusFilter || undefined);
      requests = result.requests;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  // openDeepLinkedRequest resolves the request named by a scanned QR
  // code and opens its approve dialog -- the default "pending" filter
  // usually already has it loaded, but a direct fetch covers a filter
  // change or a request that isn't on the first page of any future
  // pagination. A 404 here is the normal shape of "an application
  // owner scanned a code for a request outside their own application"
  // (backend returns 404, not 403, to avoid confirming the id exists),
  // not necessarily an error worth alarming over.
  async function openDeepLinkedRequest(id: string) {
    let target = requests.find((r) => r.id === id) ?? null;
    if (!target) {
      try {
        target = await api.getRequest(id);
      } catch (e) {
        deepLinkNotice =
          e instanceof ApiError && e.status === 404
            ? "That request could not be found -- it may not exist, or you may not have access to its application."
            : `Could not load that request: ${e instanceof Error ? e.message : String(e)}`;
        onHandledDeepLink?.();
        return;
      }
    }
    if (target.status !== "pending") {
      deepLinkNotice = `This request is already ${target.status} -- there is nothing left to approve.`;
      onHandledDeepLink?.();
      return;
    }
    openApprove(target);
    onHandledDeepLink?.();
  }

  onMount(async () => {
    await load();
    if (openRequestId) {
      await openDeepLinkedRequest(openRequestId);
    }
  });

  function openApprove(r: ApprovalRequest) {
    approveTarget = r;
    approveDialogOpen = true;
  }

  async function confirmApprove({ days, message }: { days: number; reason: string; message: string }) {
    const r = approveTarget;
    if (!r) return;
    const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    busyId = r.id;
    try {
      await api.approveRequest(r.id, {
        version: r.version,
        expires_at: expiresAt,
        label: r.label,
        ...(message ? { private_note: message } : {}),
      });
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }

  function openDeny(r: ApprovalRequest) {
    denyTarget = r;
    denyDialogOpen = true;
  }

  async function confirmDeny(reason: string) {
    const r = denyTarget;
    if (!r) return;
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

  function statusBadgeClass(status: string): string {
    switch (status) {
      case "pending":
        return "badge-warning";
      case "approved":
      case "claimed":
        return "badge-success";
      case "denied":
      case "timed_out":
      case "claim_expired":
        return "badge-danger";
      default:
        return "badge-neutral";
    }
  }
</script>

<section>
  <div class="section-header">
    <h2>Requests</h2>
    <div class="toolbar">
      <label class="field inline">
        <span class="field-label">Status</span>
        <select bind:value={statusFilter} onchange={load}>
          <option value="pending">Pending</option>
          <option value="approved">Approved (awaiting claim)</option>
          <option value="claimed">Claimed</option>
          <option value="denied">Denied</option>
          <option value="">All</option>
        </select>
      </label>
      <button class="btn" onclick={load}>Refresh</button>
    </div>
  </div>

  {#if error}
    <p role="alert" class="error-text">{error}</p>
  {/if}

  {#if deepLinkNotice}
    <p role="alert" class="notice-text">
      {deepLinkNotice}
      <button class="btn btn-ghost btn-sm" onclick={() => (deepLinkNotice = null)}>Dismiss</button>
    </p>
  {/if}

  {#if requests.length === 0}
    <p class="muted">No requests in this state.</p>
  {:else}
    <div class="card table-card">
      <table class="data-table">
        <thead>
          <tr>
            <th>Application</th>
            <th>Label</th>
            <th>Device</th>
            <th title="Supplied by the anonymous requester -- not verified as coming from anyone in particular">Message (unverified)</th>
            <th>Code</th>
            <th>Status</th>
            <th>Requested</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each requests as r (r.id)}
            <tr>
              <td title={r.application_hostname}>{r.application_display_name}</td>
              <td>{r.label ?? "—"}</td>
              <td class="device" title={r.user_agent ?? ""}>
                {r.source_ip ?? "—"}
                {#if r.source_geo_city || r.source_geo_country}
                  <span class="muted">({[r.source_geo_city, r.source_geo_country].filter(Boolean).join(", ")})</span>
                {/if}
                {#if r.user_agent}<br /><span class="muted user-agent">{r.user_agent}</span>{/if}
              </td>
              <td class="message-cell">{r.message ?? "—"}</td>
              <td class="mono">{r.verification_code}</td>
              <td><span class="badge {statusBadgeClass(r.status)}">{r.status}</span></td>
              <td title={formatDateTime(r.requested_at)}>{formatRelative(r.requested_at)}</td>
              <td class="actions">
                {#if r.status === "pending"}
                  <button class="btn btn-primary btn-sm" disabled={busyId === r.id} onclick={() => openApprove(r)}>Approve</button>
                  <button class="btn btn-danger btn-sm" disabled={busyId === r.id} onclick={() => openDeny(r)}>Deny</button>
                {/if}
                <button class="btn btn-sm" onclick={() => openNotes(r)}>Notes</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<DurationDialog
  bind:open={approveDialogOpen}
  title="Approve access"
  description={approveTarget?.message ? `Unverified text supplied by the requester: “${approveTarget.message}” -- this is not proof of who is asking; verify independently before approving.` : undefined}
  confirmLabel="Approve"
  initialDays={Math.max(1, Math.round(me.default_authorization_duration_seconds / 86400))}
  maxDays={Math.max(1, Math.round(me.max_authorization_duration_seconds / 86400))}
  messageField
  messageLabel="Note (optional)"
  onConfirm={confirmApprove}
/>

<ReasonDialog
  bind:open={denyDialogOpen}
  title="Deny request"
  description="Recorded privately, not shown to the requester."
  confirmLabel="Deny"
  danger
  onConfirm={confirmDeny}
/>

<NotesDialog
  bind:open={notesDialogOpen}
  title="Notes"
  readOnly={me.role !== "administrator" && me.role !== "application_owner"}
  loadNotes={() => api.listRequestNotes(notesTarget!.id).then((r) => r.notes)}
  onAddNote={(body) => api.addRequestNote(notesTarget!.id, { body }).then(() => {})}
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
  .field.inline {
    flex-direction: row;
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
  .device,
  .message-cell {
    max-width: 14rem;
  }
  .user-agent {
    display: inline-block;
    max-width: 14rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    vertical-align: bottom;
    font-size: var(--font-size-xs);
  }
  .actions {
    display: flex;
    gap: var(--space-2);
    white-space: nowrap;
  }
  .notice-text {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    margin-bottom: var(--space-3);
    background: var(--color-accent-soft);
    color: var(--color-accent);
    border-radius: var(--radius-sm);
  }
</style>
