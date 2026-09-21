<script lang="ts">
  // A rendered form, not a browser confirm(), for a plain yes/no
  // mutation that needs no free-text input at all (unlike ReasonDialog,
  // which requires one) -- e.g. toggling a boolean application setting.
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
    onConfirm: () => void;
  } = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();

  $effect(() => {
    if (!dialogEl) return;
    if (open && !dialogEl.open) {
      dialogEl.showModal();
    } else if (!open && dialogEl.open) {
      dialogEl.close();
    }
  });

  function close() {
    open = false;
  }

  function confirm() {
    onConfirm();
    open = false;
  }
</script>

<dialog class="modal" bind:this={dialogEl} onclose={close} onclick={(e) => { if (e.target === dialogEl) close(); }}>
  <div class="modal-body">
    <h3 class="modal-title">{title}</h3>
    {#if description}
      <p class="muted">{description}</p>
    {/if}

    <div class="modal-actions">
      <button type="button" class="btn btn-ghost" onclick={close}>Cancel</button>
      <button type="button" class="btn {danger ? 'btn-danger' : 'btn-primary'}" onclick={confirm}>{confirmLabel}</button>
    </div>
  </div>
</dialog>
