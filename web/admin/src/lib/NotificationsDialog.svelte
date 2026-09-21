<script lang="ts">
  // A rendered form, not two sequential browser prompt()s, for an
  // application's notify_email/notify_webhook_url overrides -- both
  // fields in one submit, instead of two separate native dialogs each
  // of which could be individually canceled halfway through.
  let {
    open = $bindable(false),
    title,
    description = "",
    initialEmail = "",
    initialWebhookURL = "",
    onConfirm,
  }: {
    open: boolean;
    title: string;
    description?: string;
    initialEmail?: string;
    initialWebhookURL?: string;
    onConfirm: (result: { email: string; webhookURL: string }) => void;
  } = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  let email = $state("");
  let webhookURL = $state("");

  $effect(() => {
    if (!dialogEl) return;
    if (open && !dialogEl.open) {
      email = initialEmail;
      webhookURL = initialWebhookURL;
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
    onConfirm({ email: email.trim(), webhookURL: webhookURL.trim() });
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
      <span class="field-label">Notification email</span>
      <input type="text" bind:value={email} placeholder="Leave blank to use the deployment-wide default" maxlength="320" />
    </label>

    <label class="field">
      <span class="field-label">Notification webhook URL</span>
      <input type="text" bind:value={webhookURL} placeholder="Leave blank to use the deployment-wide default" />
      <span class="field-hint">Must be an absolute http(s) URL if set.</span>
    </label>

    <div class="modal-actions">
      <button type="button" class="btn btn-ghost" onclick={close}>Cancel</button>
      <button type="submit" class="btn btn-primary">Save</button>
    </div>
  </form>
</dialog>
