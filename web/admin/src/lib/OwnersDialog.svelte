<script lang="ts">
  // A rendered list with per-row remove buttons plus an add-owner
  // field, not a single comma-separated-list prompt() -- replaces
  // manageOwners' old editor (the one whose null-vs-[] JSON bug made
  // the Owners button appear to do nothing). Mirrors NotesDialog's
  // load-on-open/refresh-after-mutate pattern.
  let {
    open = $bindable(false),
    title,
    loadOwners,
    onGrant,
    onRevoke,
  }: {
    open: boolean;
    title: string;
    loadOwners: () => Promise<string[]>;
    onGrant: (subject: string) => Promise<void>;
    onRevoke: (subject: string) => Promise<void>;
  } = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  let owners: string[] = $state([]);
  let newSubject = $state("");
  let loading = $state(false);
  let busySubject: string | null = $state(null);
  let formError: string | null = $state(null);

  $effect(() => {
    if (!dialogEl) return;
    if (open && !dialogEl.open) {
      newSubject = "";
      formError = null;
      dialogEl.showModal();
      refresh();
    } else if (!open && dialogEl.open) {
      dialogEl.close();
    }
  });

  async function refresh() {
    loading = true;
    formError = null;
    try {
      owners = await loadOwners();
    } catch (e) {
      formError = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  function close() {
    open = false;
  }

  async function addOwner(event: SubmitEvent) {
    event.preventDefault();
    const subject = newSubject.trim();
    if (subject === "") return;
    busySubject = subject;
    formError = null;
    try {
      await onGrant(subject);
      newSubject = "";
      await refresh();
    } catch (e) {
      formError = e instanceof Error ? e.message : String(e);
    } finally {
      busySubject = null;
    }
  }

  async function removeOwner(subject: string) {
    busySubject = subject;
    formError = null;
    try {
      await onRevoke(subject);
      await refresh();
    } catch (e) {
      formError = e instanceof Error ? e.message : String(e);
    } finally {
      busySubject = null;
    }
  }
</script>

<dialog class="modal" bind:this={dialogEl} onclose={close} onclick={(e) => { if (e.target === dialogEl) close(); }}>
  <div class="modal-body">
    <h3 class="modal-title">{title}</h3>
    <p class="muted">An ApplicationOwner can approve/deny requests and revoke sessions for this application only.</p>

    {#if loading}
      <p class="muted">Loading…</p>
    {:else if owners.length === 0}
      <p class="muted">No owners yet.</p>
    {:else}
      <ul class="owners-list">
        {#each owners as subject (subject)}
          <li>
            <span class="mono">{subject}</span>
            <button type="button" class="btn btn-ghost btn-sm" disabled={busySubject === subject} onclick={() => removeOwner(subject)}>Remove</button>
          </li>
        {/each}
      </ul>
    {/if}

    <form onsubmit={addOwner}>
      <label class="field">
        <span class="field-label">Add owner (OIDC subject, e.g. an email address)</span>
        <input type="text" bind:value={newSubject} placeholder="owner@example.com" />
      </label>
      {#if formError}
        <p class="error-text">{formError}</p>
      {/if}
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" onclick={close}>Close</button>
        <button type="submit" class="btn btn-primary" disabled={busySubject !== null || newSubject.trim() === ""}>Add</button>
      </div>
    </form>
  </div>
</dialog>

<style>
  .owners-list {
    list-style: none;
    margin: 0;
    padding: 0;
    max-height: 16rem;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .owners-list li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-sm);
    padding: var(--space-2);
  }
  .mono {
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
  }
</style>
