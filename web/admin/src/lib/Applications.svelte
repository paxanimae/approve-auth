<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "./api";
  import type { Application } from "./types";
  import { formatDateTime } from "./format";

  let applications: Application[] = $state([]);
  let error: string | null = $state(null);
  let busyId: string | null = $state(null);

  let newHostname = $state("");
  let newDisplayName = $state("");
  let newContactInfo = $state("");
  let creating = $state(false);
  let createError: string | null = $state(null);

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

  async function editContactInfo(a: Application) {
    const current = a.contact_info ?? "";
    const next = prompt(
      `Contact info shown on ${a.hostname}'s request page.\nLeave blank to use the global default instead of an override.`,
      current,
    );
    if (next === null || next === current) return;
    busyId = a.id;
    try {
      await api.updateApplication(a.id, { version: a.version, contact_info: next });
      await load();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      busyId = null;
    }
  }

  async function disable(a: Application) {
    const reason = prompt(`Reason for disabling ${a.hostname} (this cancels its pending requests and revokes all active sessions):`);
    if (reason === null || reason.trim() === "") return;
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
            <td class="actions">
              {#if a.enabled}
                <button class="btn btn-danger btn-sm" disabled={busyId === a.id} onclick={() => disable(a)}>Disable</button>
              {:else}
                <button class="btn btn-sm" disabled={busyId === a.id} onclick={() => enable(a)}>Enable</button>
              {/if}
              <button class="btn btn-sm" disabled={busyId === a.id} onclick={() => editContactInfo(a)}>Edit contact info</button>
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
