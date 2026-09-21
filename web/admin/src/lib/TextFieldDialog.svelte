<script lang="ts">
  // A rendered form, not a browser prompt(), for editing a single
  // optional text field prefilled with its current value -- used for
  // an application's own contact_info override. An empty submission
  // is a valid, meaningful value here (it clears the override back to
  // the deployment-wide default), so it's never treated as "no
  // change" the way ReasonDialog's required field is.
  let {
    open = $bindable(false),
    title,
    description = "",
    fieldLabel,
    placeholder = "",
    initialValue = "",
    maxLength,
    confirmLabel = "Save",
    onConfirm,
  }: {
    open: boolean;
    title: string;
    description?: string;
    fieldLabel: string;
    placeholder?: string;
    initialValue?: string;
    maxLength?: number;
    confirmLabel?: string;
    onConfirm: (value: string) => void;
  } = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  let value = $state("");

  $effect(() => {
    if (!dialogEl) return;
    if (open && !dialogEl.open) {
      value = initialValue;
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
    onConfirm(value.trim());
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
      <span class="field-label">{fieldLabel}</span>
      <input type="text" bind:value {placeholder} maxlength={maxLength} />
    </label>

    <div class="modal-actions">
      <button type="button" class="btn btn-ghost" onclick={close}>Cancel</button>
      <button type="submit" class="btn btn-primary">{confirmLabel}</button>
    </div>
  </form>
</dialog>
