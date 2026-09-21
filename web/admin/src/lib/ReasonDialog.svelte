<script lang="ts">
  // A rendered form, not a browser prompt(), for every mutation that
  // needs one free-text reason before proceeding: deny (Requests),
  // revoke (Sessions), disable (Applications). The Confirm button
  // itself is the confirmation step -- unlike the revoke flow's old
  // prompt()-then-confirm() pair, there's no need for a second native
  // dialog on top of this one.
  let {
    open = $bindable(false),
    title,
    description = "",
    confirmLabel = "Confirm",
    danger = false,
    onConfirm,
  }: {
    open: boolean;
    title: string;
    description?: string;
    confirmLabel?: string;
    danger?: boolean;
    onConfirm: (reason: string) => void;
  } = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  let reason = $state("");
  let formError: string | null = $state(null);

  $effect(() => {
    if (!dialogEl) return;
    if (open && !dialogEl.open) {
      reason = "";
      formError = null;
      dialogEl.showModal();
    } else if (!open && dialogEl.open) {
      dialogEl.close();
    }
  });

  function close() {
    open = false;
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const trimmed = reason.trim();
    if (trimmed === "") {
      formError = "A reason is required.";
      return;
    }
    onConfirm(trimmed);
    open = false;
  }
</script>

<dialog class="modal" bind:this={dialogEl} onclose={close} onclick={(e) => { if (e.target === dialogEl) close(); }}>
  <form class="modal-body" onsubmit={submit}>
    <h3 class="modal-title">{title}</h3>
    {#if description}
      <p class="muted">{description}</p>
    {/if}

    <label class="field">
      <span class="field-label">Reason</span>
      <textarea bind:value={reason} rows="3" placeholder="Recorded in the audit log" required></textarea>
    </label>

    {#if formError}
      <p class="error-text">{formError}</p>
    {/if}

    <div class="modal-actions">
      <button type="button" class="btn btn-ghost" onclick={close}>Cancel</button>
      <button type="submit" class="btn {danger ? 'btn-danger' : 'btn-primary'}">{confirmLabel}</button>
    </div>
  </form>
</dialog>
