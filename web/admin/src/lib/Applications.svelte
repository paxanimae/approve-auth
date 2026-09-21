<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "./api";
  import type { Application, RevokePolicyAction } from "./types";
  import { formatDateTime } from "./format";
  import TextFieldDialog from "./TextFieldDialog.svelte";
  import NotificationsDialog from "./NotificationsDialog.svelte";
  import RevocationPolicyDialog from "./RevocationPolicyDialog.svelte";
  import OwnersDialog from "./OwnersDialog.svelte";
  import ReasonDialog from "./ReasonDialog.svelte";
  import ConfirmDialog from "./ConfirmDialog.svelte";

  let applications: Application[] = $state([]);
  let error: string | null = $state(null);
  let busyId: string | null = $state(null);

  let newHostname = $state("");
  let newDisplayName = $state("");
  let newContactInfo = $state("");
  let creating = $state(false);
  let createError: string | null = $state(null);

  let contactInfoDialogOpen = $state(false);
  let notificationsDialogOpen = $state(false);
  let revocationPolicyDialogOpen = $state(false);
  let ownersDialogOpen = $state(false);
  let disableDialogOpen = $state(false);
  let dialogTarget: Application | null = $state(null);

  async function load() {
    error = null;
    try {
      const result = await api.listApplications();
      applications = result.applications;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  onMount(load);

  async function createApplication(event: SubmitEvent) {
    event.preventDefault();
    createError = null;
    if (!newHostname.trim() || !newDisplayName.trim()) {
      createError = "Hostname and display name are required.";
      return;
    }
    creating = true;
    try {
      await api.createApplication({
        hostname: newHostname.trim(),
        display_name: newDisplayName.trim(),
        contact_info: newContactInfo.trim() || undefined,
      });
      newHostname = "";
      newDisplayName = "";
      newContactInfo = "";
      await load();
    } catch (e) {
      createError = e instanceof Error ? e.message : String(e);
    } finally {
      creating = false;
    }
  }

  function openContactInfo(a: Application) {
    dialogTarget = a;
    contactInfoDialogOpen = true;
  }

  async function confirmContactInfo(value: string) {
    const a = dialogTarget;
    if (!a || value === (a.contact_info ?? "")) return;
    busyId = a.id;
    try {
      await api.updateApplication(a.id, { version: a.version, contact_info: value });
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }

  function openNotifications(a: Application) {
    dialogTarget = a;
    notificationsDialogOpen = true;
  }

  async function confirmNotifications({ email, webhookURL }: { email: string; webhookURL: string }) {
    const a = dialogTarget;
    if (!a) return;
    if (email === (a.notify_email ?? "") && webhookURL === (a.notify_webhook_url ?? "")) return;
    busyId = a.id;
    try {
      await api.updateApplication(a.id, { version: a.version, notify_email: email, notify_webhook_url: webhookURL });
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }

  function openRevocationPolicy(a: Application) {
    dialogTarget = a;
    revocationPolicyDialogOpen = true;
  }

  async function confirmRevocationPolicy({
    ipChanged,
    userAgentChanged,
    inactivityExceeded,
  }: {
    ipChanged: RevokePolicyAction | "";
    userAgentChanged: RevokePolicyAction | "";
    inactivityExceeded: RevokePolicyAction | "";
  }) {
    const a = dialogTarget;
    if (!a) return;
    if (
      ipChanged === (a.revoke_policy_ip_changed ?? "") &&
      userAgentChanged === (a.revoke_policy_user_agent_changed ?? "") &&
      inactivityExceeded === (a.revoke_policy_inactivity_exceeded ?? "")
    ) {
      return;
    }
    busyId = a.id;
    try {
      await api.updateApplication(a.id, {
        version: a.version,
        revoke_policy_ip_changed: ipChanged,
        revoke_policy_user_agent_changed: userAgentChanged,
        revoke_policy_inactivity_exceeded: inactivityExceeded,
      });
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }

  function openDisable(a: Application) {
    dialogTarget = a;
    disableDialogOpen = true;
  }

  async function confirmDisable(reason: string) {
    const a = dialogTarget;
    if (!a) return;
    busyId = a.id;
    try {
      const result = await api.disableApplication(a.id, { version: a.version, reason });
      alert(`Disabled. Canceled ${result.canceled_requests} pending request(s), revoked ${result.revoked_authorizations} session(s).`);
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }

  async function enable(a: Application) {
    busyId = a.id;
    try {
      await api.enableApplication(a.id, { version: a.version });
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }

  function openOwners(a: Application) {
    dialogTarget = a;
    ownersDialogOpen = true;
  }

  let allowMessageDialogOpen = $state(false);

  // toggleAllowAnonymousMessage flips AllowAnonymousMessage (endpoint-
  // review.md F3: false by default for every application). Turning it
  // ON confirms first via a rendered dialog, since anonymous free text
  // is never verified as coming from anyone in particular; turning it
  // back OFF needs no confirmation.
  function requestToggleAllowAnonymousMessage(a: Application) {
    if (a.allow_anonymous_message) {
      void applyAllowAnonymousMessage(a, false);
      return;
    }
    dialogTarget = a;
    allowMessageDialogOpen = true;
  }

  async function applyAllowAnonymousMessage(a: Application, value: boolean) {
    busyId = a.id;
    try {
      await api.updateApplication(a.id, { version: a.version, allow_anonymous_message: value });
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }
</script>

<section>
  <h2>Applications</h2>

  {#if error}
    <p role="alert" class="error-text">{error}</p>
  {/if}

  <div class="card table-card">
    <table class="data-table">
      <thead>
        <tr>
          <th>Hostname</th>
          <th>Display name</th>
          <th>State</th>
          <th>Default duration</th>
          <th>Contact info</th>
          <th title="Whether the anonymous request page may accept a label/message">Anonymous messages</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each applications as a (a.id)}
          <tr>
            <td class="mono">{a.hostname}</td>
            <td>{a.display_name}</td>
            <td><span class="badge {a.enabled ? 'badge-success' : 'badge-neutral'}">{a.enabled ? "enabled" : "disabled"}</span></td>
            <td title={formatDateTime(a.created_at)}>{Math.round(a.default_duration_seconds / 86400)} days</td>
            <td class="contact-info-cell">{a.contact_info ?? "(global default)"}</td>
            <td>
              <button
                class="btn btn-sm"
                disabled={busyId === a.id}
                onclick={() => requestToggleAllowAnonymousMessage(a)}
              >
                {a.allow_anonymous_message ? "Allowed" : "Blocked"}
              </button>
            </td>
            <td class="actions">
              {#if a.enabled}
                <button class="btn btn-danger btn-sm" disabled={busyId === a.id} onclick={() => openDisable(a)}>Disable</button>
              {:else}
                <button class="btn btn-sm" disabled={busyId === a.id} onclick={() => enable(a)}>Enable</button>
              {/if}
              <button class="btn btn-sm" disabled={busyId === a.id} onclick={() => openContactInfo(a)}>Edit contact info</button>
              <button class="btn btn-sm" disabled={busyId === a.id} onclick={() => openNotifications(a)}>Notifications</button>
              <button class="btn btn-sm" disabled={busyId === a.id} onclick={() => openRevocationPolicy(a)}>Revocation policy</button>
              <button class="btn btn-sm" disabled={busyId === a.id} onclick={() => openOwners(a)}>Owners</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>

  <div class="card register-card">
    <h3>Register a new application</h3>
    <form onsubmit={createApplication}>
      <label class="field">
        <span class="field-label">Hostname</span>
        <input type="text" bind:value={newHostname} placeholder="app.example.com" required />
      </label>
      <label class="field">
        <span class="field-label">Display name</span>
        <input type="text" bind:value={newDisplayName} placeholder="Internal Dashboard" required />
      </label>
      <label class="field">
        <span class="field-label">Contact info (optional)</span>
        <input type="text" bind:value={newContactInfo} placeholder="Leave blank to use the global default" maxlength="500" />
      </label>
      <button type="submit" class="btn btn-primary" disabled={creating}>Register</button>
    </form>
    {#if createError}
      <p role="alert" class="error-text">{createError}</p>
    {/if}
  </div>
</section>

<TextFieldDialog
  bind:open={contactInfoDialogOpen}
  title="Edit contact info"
  description={dialogTarget ? `Shown on ${dialogTarget.hostname}'s request page. Leave blank to use the deployment-wide default instead of an override.` : undefined}
  fieldLabel="Contact info"
  initialValue={dialogTarget?.contact_info ?? ""}
  maxLength={500}
  onConfirm={confirmContactInfo}
/>

<NotificationsDialog
  bind:open={notificationsDialogOpen}
  title="Notifications"
  description={dialogTarget ? `Overrides for ${dialogTarget.hostname}. Leave a field blank to use the deployment-wide default instead.` : undefined}
  initialEmail={dialogTarget?.notify_email ?? ""}
  initialWebhookURL={dialogTarget?.notify_webhook_url ?? ""}
  onConfirm={confirmNotifications}
/>

<RevocationPolicyDialog
  bind:open={revocationPolicyDialogOpen}
  title={dialogTarget ? `Revocation policy for ${dialogTarget.hostname}` : "Revocation policy"}
  initialIPChanged={dialogTarget?.revoke_policy_ip_changed ?? ""}
  initialUserAgentChanged={dialogTarget?.revoke_policy_user_agent_changed ?? ""}
  initialInactivityExceeded={dialogTarget?.revoke_policy_inactivity_exceeded ?? ""}
  onConfirm={confirmRevocationPolicy}
/>

<OwnersDialog
  bind:open={ownersDialogOpen}
  title={dialogTarget ? `Owners of ${dialogTarget.hostname}` : "Owners"}
  loadOwners={() => api.listApplicationOwners(dialogTarget!.id).then((r) => r.owners)}
  onGrant={(subject) => api.grantApplicationOwner(dialogTarget!.id, subject).then(() => {})}
  onRevoke={(subject) => api.revokeApplicationOwner(dialogTarget!.id, subject).then(() => {})}
/>

<ReasonDialog
  bind:open={disableDialogOpen}
  title="Disable application"
  description={dialogTarget ? `Disabling ${dialogTarget.hostname} cancels its pending requests and revokes all active sessions.` : undefined}
  confirmLabel="Disable"
  danger
  onConfirm={confirmDisable}
/>

<ConfirmDialog
  bind:open={allowMessageDialogOpen}
  title="Allow anonymous messages"
  description={dialogTarget
    ? `Allow ${dialogTarget.hostname}'s request page to accept a label/message from an anonymous requester? This text is never verified as coming from anyone in particular -- review it as unverified in Requests before acting on it.`
    : undefined}
  confirmLabel="Allow"
  onConfirm={() => dialogTarget && applyAllowAnonymousMessage(dialogTarget, true)}
/>

<style>
  h2 {
    margin-bottom: var(--space-4);
  }
  .table-card {
    overflow-x: auto;
    margin-bottom: var(--space-5);
  }
  .register-card {
    padding: var(--space-4);
  }
  .register-card h3 {
    margin-bottom: var(--space-3);
    font-size: var(--font-size-base);
  }
  .mono {
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
  }
  form {
    display: flex;
    flex-wrap: wrap;
    align-items: end;
    gap: var(--space-3);
  }
  .actions {
    white-space: nowrap;
  }
  .contact-info-cell {
    max-width: 16rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--color-text-muted);
  }
</style>
