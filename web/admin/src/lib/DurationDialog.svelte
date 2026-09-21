<script lang="ts">
  // A rendered form, not a browser prompt()/confirm() dialog, for every
  // place the console asks an admin to choose a session lifetime
  // (approve, renew). "Permanent" fills in the server's actual
  // configured maximum (maxDays) rather than a client-side guess --
  // Approve/Renew both hard-reject anything beyond that ceiling
  // (spec: access is always time-limited, never truly infinite).
  let {
    open = $bindable(false),
    title,
    description = "",
    confirmLabel = "Confirm",
    initialDays = 30,
    maxDays,
    reasonRequired = false,
    messageField = false,
    messageLabel = "Message (optional)",
    initialMessage = "",
    onConfirm,
  }: {
    open: boolean;
    title: string;
    description?: string;
    confirmLabel?: string;
    initialDays?: number;
    maxDays: number;
    reasonRequired?: boolean;
    // messageField adds a free-text note to the dialog (e.g. approve's
    // private_note) -- off by default so renew's own use of this same
    // dialog is unaffected.
    messageField?: boolean;
    messageLabel?: string;
    initialMessage?: string;
    onConfirm: (result: { days: number; reason: string; message: string }) => void;
  } = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  // Real value is set by the $effect below whenever the dialog opens --
  // this initializer only matters before that first run.
  let days = $state(0);
  let permanent = $state(false);
  let reason = $state("");
  let message = $state("");
  let formError: string | null = $state(null);

  $effect(() => {
    if (!dialogEl) return;
    if (open && !dialogEl.open) {
      days = initialDays;
      permanent = false;
      reason = "";
      message = initialMessage;
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
    const chosenDays = permanent ? maxDays : Math.floor(days);
    if (!permanent && (!Number.isFinite(chosenDays) || chosenDays <= 0)) {
      formError = "Enter a positive number of days.";
      return;
    }
    if (chosenDays > maxDays) {
      formError = `This server allows at most ${maxDays} days.`;
      return;
    }
    if (reasonRequired && reason.trim() === "") {
      formError = "A reason is required.";
      return;
    }
    onConfirm({ days: chosenDays, reason: reason.trim(), message: message.trim() });
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
      <span class="field-label">Duration (days)</span>
      <input type="number" min="1" max={maxDays} bind:value={days} disabled={permanent} required={!permanent} />
    </label>

    <label class="checkbox-row">
      <input type="checkbox" bind:checked={permanent} />
      Permanent (uses the maximum this server allows: {maxDays} days)
    </label>

    {#if reasonRequired}
      <label class="field">
        <span class="field-label">Reason</span>
        <textarea bind:value={reason} rows="2" placeholder="Recorded in the audit log"></textarea>
      </label>
    {/if}

    {#if messageField}
      <label class="field">
        <span class="field-label">{messageLabel}</span>
        <textarea bind:value={message} rows="2" placeholder="Visible to other admins, not to the requester"></textarea>
      </label>
    {/if}

    {#if formError}
      <p class="error-text">{formError}</p>
    {/if}

    <div class="modal-actions">
      <button type="button" class="btn btn-ghost" onclick={close}>Cancel</button>
      <button type="submit" class="btn btn-primary">{confirmLabel}</button>
    </div>
  </form>
</dialog>
