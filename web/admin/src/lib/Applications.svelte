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
      await api.createApplication({ hostname: newHostname.trim(), display_name: newDisplayName.trim() });
      newHostname = "";
      newDisplayName = "";
      await load();
    } catch (e) {
      createError = e instanceof Error ? e.message : String(e);
    } finally {
      creating = false;
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
    <p role="alert" class="error">{error}</p>
  {/if}

  <table>
    <thead>
      <tr>
        <th>Hostname</th>
        <th>Display name</th>
        <th>State</th>
        <th>Default duration</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {#each applications as a (a.id)}
        <tr>
          <td>{a.hostname}</td>
          <td>{a.display_name}</td>
          <td>{a.enabled ? "enabled" : "disabled"}</td>
          <td title={formatDateTime(a.created_at)}>{Math.round(a.default_duration_seconds / 86400)} days</td>
          <td>
            {#if a.enabled}
              <button disabled={busyId === a.id} class="danger" onclick={() => disable(a)}>Disable</button>
            {:else}
              <button disabled={busyId === a.id} onclick={() => enable(a)}>Enable</button>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>

  <h3>Register a new application</h3>
  <form onsubmit={createApplication}>
    <label>
      Hostname
      <input type="text" bind:value={newHostname} placeholder="app.example.com" required />
    </label>
    <label>
      Display name
      <input type="text" bind:value={newDisplayName} placeholder="Internal Dashboard" required />
    </label>
    <button type="submit" disabled={creating}>Register</button>
    {#if createError}
      <p role="alert" class="error">{createError}</p>
    {/if}
  </form>
</section>

<style>
  table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: var(--space-4);
  }
  th, td {
    text-align: left;
    padding: var(--space-2);
    border-bottom: 1px solid var(--color-border);
  }
  form {
    display: flex;
    flex-wrap: wrap;
    align-items: end;
    gap: var(--space-3);
  }
  label {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }
  .error {
    color: var(--color-danger);
  }
  button.danger {
    color: var(--color-danger);
  }
</style>
