<script lang="ts">
  // Click-to-define <select> dropdowns over the 4 fixed
  // internal/revokepolicy actions, not free-text entry -- replaces
  // the old three-sequential-prompt() editor. inheritLabel's value
  // ("") is only offered here (an application override, unlike the
  // deployment-wide default this same option list backs on the
  // Settings page, has something to inherit from); see revokePolicy.ts
  // for the shared, non-inherit option list both places render.
  import type { RevokePolicyAction } from "./types";
  import { revokePolicyOptions } from "./revokePolicy";

  let {
    open = $bindable(false),
    title,
    inheritLabel = "(inherit the deployment-wide default)",
    initialIPChanged = "",
    initialUserAgentChanged = "",
    initialInactivityExceeded = "",
    onConfirm,
  }: {
    open: boolean;
    title: string;
    inheritLabel?: string;
    initialIPChanged?: RevokePolicyAction | "";
    initialUserAgentChanged?: RevokePolicyAction | "";
    initialInactivityExceeded?: RevokePolicyAction | "";
    onConfirm: (result: {
      ipChanged: RevokePolicyAction | "";
      userAgentChanged: RevokePolicyAction | "";
      inactivityExceeded: RevokePolicyAction | "";
    }) => void;
  } = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  let ipChanged: RevokePolicyAction | "" = $state("");
  let userAgentChanged: RevokePolicyAction | "" = $state("");
  let inactivityExceeded: RevokePolicyAction | "" = $state("");

  $effect(() => {
    if (!dialogEl) return;
    if (open && !dialogEl.open) {
      ipChanged = initialIPChanged;
      userAgentChanged = initialUserAgentChanged;
      inactivityExceeded = initialInactivityExceeded;
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
    onConfirm({ ipChanged, userAgentChanged, inactivityExceeded });
    open = false;
  }
</script>

<dialog class="modal" bind:this={dialogEl} onclose={close} onclick={(e) => { if (e.target === dialogEl) close(); }}>
  <form class="modal-body" onsubmit={submit}>
    <h3 class="modal-title">{title}</h3>

    <label class="field">
      <span class="field-label">IP changed</span>
      <select bind:value={ipChanged}>
        <option value="">{inheritLabel}</option>
        {#each revokePolicyOptions as o (o.value)}
          <option value={o.value}>{o.label}</option>
        {/each}
      </select>
    </label>

    <label class="field">
      <span class="field-label">User-Agent changed</span>
      <select bind:value={userAgentChanged}>
        <option value="">{inheritLabel}</option>
        {#each revokePolicyOptions as o (o.value)}
          <option value={o.value}>{o.label}</option>
        {/each}
      </select>
    </label>

    <label class="field">
      <span class="field-label">Inactivity exceeded</span>
      <select bind:value={inactivityExceeded}>
        <option value="">{inheritLabel}</option>
        {#each revokePolicyOptions as o (o.value)}
          <option value={o.value}>{o.label}</option>
        {/each}
      </select>
    </label>

    <div class="modal-actions">
      <button type="button" class="btn btn-ghost" onclick={close}>Cancel</button>
      <button type="submit" class="btn btn-primary">Save</button>
    </div>
  </form>
</dialog>
