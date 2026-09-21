<script lang="ts">
  // Shared viewer for both a request's and an authorization's notes --
  // identical shape (see types.ts's Note), just fed by different
  // loadNotes/onAddNote callbacks depending on which one opened it.
  // Notes are append-only server-side; there is deliberately no edit
  // or delete here either.
  import type { Note } from "./types";
  import { formatDateTime } from "./format";

  let {
    open = $bindable(false),
    title,
    readOnly = false,
    loadNotes,
    onAddNote,
  }: {
    open: boolean;
    title: string;
    readOnly?: boolean;
    loadNotes: () => Promise<Note[]>;
    onAddNote: (body: string) => Promise<void>;
  } = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  let notes: Note[] = $state([]);
  let newBody = $state("");
  let loading = $state(false);
  let submitting = $state(false);
  let formError: string | null = $state(null);

  $effect(() => {
    if (!dialogEl) return;
    if (open && !dialogEl.open) {
      newBody = "";
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
      notes = await loadNotes();
    } catch (e) {
      formError = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  function close() {
    open = false;
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const body = newBody.trim();
    if (!body) {
      formError = "Enter a note.";
      return;
    }
    submitting = true;
    formError = null;
    try {
      await onAddNote(body);
      newBody = "";
      await refresh();
    } catch (e) {
      formError = e instanceof Error ? e.message : String(e);
    } finally {
      submitting = false;
    }
  }
</script>

<dialog class="modal" bind:this={dialogEl} onclose={close} onclick={(e) => { if (e.target === dialogEl) close(); }}>
  <div class="modal-body">
    <h3 class="modal-title">{title}</h3>

    {#if loading}
      <p class="muted">Loading…</p>
    {:else if notes.length === 0}
      <p class="muted">No notes yet.</p>
    {:else}
      <ul class="notes-list">
        {#each notes as n (n.id)}
          <li>
            <div class="note-meta muted">{n.author_subject} &middot; {formatDateTime(n.created_at)}</div>
            <div class="note-body">{n.body}</div>
          </li>
        {/each}
      </ul>
    {/if}

    {#if !readOnly}
      <form onsubmit={submit}>
        <label class="field">
          <span class="field-label">Add a note</span>
          <textarea bind:value={newBody} rows="3" maxlength="2000" placeholder="Recorded permanently, never editable afterward"></textarea>
        </label>
        {#if formError}
          <p class="error-text">{formError}</p>
        {/if}
        <div class="modal-actions">
          <button type="button" class="btn btn-ghost" onclick={close}>Close</button>
          <button type="submit" class="btn btn-primary" disabled={submitting}>Add note</button>
        </div>
      </form>
    {:else}
      {#if formError}
        <p class="error-text">{formError}</p>
      {/if}
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" onclick={close}>Close</button>
      </div>
    {/if}
  </div>
</dialog>

<style>
  .notes-list {
    list-style: none;
    margin: 0 0 var(--space-3) 0;
    padding: 0;
    max-height: 16rem;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .notes-list li {
    border: 1px solid var(--color-border);
    border-radius: var(--radius-sm);
    padding: var(--space-2);
  }
  .note-meta {
    font-size: var(--font-size-xs);
    margin-bottom: var(--space-1);
  }
  .note-body {
    white-space: pre-wrap;
    font-size: var(--font-size-sm);
  }
</style>
