<script lang="ts">
  // The deployment-wide business-rule defaults (migration 000019's
  // global_settings) -- live-editable here, unlike everything still
  // in static YAML/env config, so a save takes effect on the very
  // next request/decision/delivery with no restart. The three
  // revocation-policy fields are the click-to-define <select>s this
  // session's plan specifically required (not free-text entry),
  // reusing the same option list RevocationPolicyDialog.svelte renders
  // for a per-application override.
  import { onMount } from "svelte";
  import { api, ApiError } from "./api";
  import type { GlobalSettings, Me, RevokePolicyAction } from "./types";
  import { revokePolicyOptions } from "./revokePolicy";

  let { me }: { me: Me } = $props();

  let readOnly = $derived(me.role !== "administrator");

  let settings: GlobalSettings | null = $state(null);
  let loadError: string | null = $state(null);

  let contactInfo = $state("");
  let notifyEmailFrom = $state("");
  let notifyDefaultEmail = $state("");
  let notifyDefaultWebhookURL = $state("");
  let revokePolicyIPChanged: RevokePolicyAction = $state("off");
  let revokePolicyUserAgentChanged: RevokePolicyAction = $state("off");
  let revokePolicyInactivityExceeded: RevokePolicyAction = $state("off");
  let inactivityThresholdDays = $state(90);

  let saving = $state(false);
  let saveError: string | null = $state(null);
  let saved = $state(false);

  function applySettings(s: GlobalSettings) {
    settings = s;
    contactInfo = s.contact_info ?? "";
    notifyEmailFrom = s.notify_email_from ?? "";
    notifyDefaultEmail = s.notify_default_email ?? "";
    notifyDefaultWebhookURL = s.notify_default_webhook_url ?? "";
    revokePolicyIPChanged = s.revoke_policy_ip_changed;
    revokePolicyUserAgentChanged = s.revoke_policy_user_agent_changed;
    revokePolicyInactivityExceeded = s.revoke_policy_inactivity_exceeded;
    inactivityThresholdDays = Math.max(1, Math.round(s.revocation_inactivity_threshold_seconds / 86400));
  }

  async function load() {
    loadError = null;
    try {
      applySettings(await api.getSettings());
    } catch (e) {
      loadError = e instanceof Error ? e.message : String(e);
    }
  }

  onMount(load);

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (!settings) return;
    saving = true;
    saveError = null;
    saved = false;
    try {
      const updated = await api.updateSettings({
        version: settings.version,
        contact_info: contactInfo,
        notify_email_from: notifyEmailFrom,
        notify_default_email: notifyDefaultEmail,
        notify_default_webhook_url: notifyDefaultWebhookURL,
        revoke_policy_ip_changed: revokePolicyIPChanged,
        revoke_policy_user_agent_changed: revokePolicyUserAgentChanged,
        revoke_policy_inactivity_exceeded: revokePolicyInactivityExceeded,
        revocation_inactivity_threshold_seconds: Math.max(1, Math.floor(inactivityThresholdDays)) * 86400,
      });
      applySettings(updated);
      saved = true;
    } catch (e) {
      if (e instanceof ApiError && e.code === "conflict") {
        saveError = "Someone else changed these settings since this page loaded. Reloading the current values.";
        await load();
      } else {
        saveError = e instanceof Error ? e.message : String(e);
      }
    } finally {
      saving = false;
    }
  }
</script>

<section>
  <h2>Settings</h2>
  <p class="muted">
    Deployment-wide defaults. An application's own override (Applications view) or a session's own override (set at approval
    time) takes priority over these.
  </p>

  {#if loadError}
    <p role="alert" class="error-text">{loadError}</p>
  {/if}

  {#if settings}
    <form class="card settings-card" onsubmit={save}>
      <fieldset disabled={readOnly}>
        <h3>Contact &amp; notifications</h3>

        <label class="field">
          <span class="field-label">Contact info</span>
          <input type="text" bind:value={contactInfo} placeholder="Shown on a request page unless that application overrides it" maxlength="500" />
        </label>

        <label class="field">
          <span class="field-label">Notification from-address</span>
          <input type="text" bind:value={notifyEmailFrom} placeholder="approve-auth@example.com" maxlength="320" />
          <span class="field-hint">Email is off entirely until notify_smtp_host is also configured (static config).</span>
        </label>

        <label class="field">
          <span class="field-label">Default notification email</span>
          <input type="text" bind:value={notifyDefaultEmail} placeholder="it@example.com" maxlength="320" />
        </label>

        <label class="field">
          <span class="field-label">Default notification webhook URL</span>
          <input type="text" bind:value={notifyDefaultWebhookURL} placeholder="https://hooks.example.com/approve-auth" />
          <span class="field-hint">Must be an absolute http(s) URL if set.</span>
        </label>

        <h3>Revocation policy</h3>
        <p class="muted field-hint">
          The action taken for each signal (internal/revokepolicy), unless a specific application or session overrides it.
        </p>

        <label class="field">
          <span class="field-label">IP changed</span>
          <select bind:value={revokePolicyIPChanged}>
            {#each revokePolicyOptions as o (o.value)}
              <option value={o.value}>{o.label}</option>
            {/each}
          </select>
        </label>

        <label class="field">
          <span class="field-label">User-Agent changed</span>
          <select bind:value={revokePolicyUserAgentChanged}>
            {#each revokePolicyOptions as o (o.value)}
              <option value={o.value}>{o.label}</option>
            {/each}
          </select>
        </label>

        <label class="field">
          <span class="field-label">Inactivity exceeded</span>
          <select bind:value={revokePolicyInactivityExceeded}>
            {#each revokePolicyOptions as o (o.value)}
              <option value={o.value}>{o.label}</option>
            {/each}
          </select>
        </label>

        <label class="field">
          <span class="field-label">Inactivity threshold (days)</span>
          <input type="number" min="1" bind:value={inactivityThresholdDays} />
          <span class="field-hint">Only applies when "Inactivity exceeded" above is not Off.</span>
        </label>
      </fieldset>

      {#if saveError}
        <p role="alert" class="error-text">{saveError}</p>
      {/if}
      {#if saved}
        <p class="success-text">Saved.</p>
      {/if}

      {#if !readOnly}
        <div class="modal-actions">
          <button type="submit" class="btn btn-primary" disabled={saving}>Save</button>
        </div>
      {:else}
        <p class="muted">Only an administrator can change these settings.</p>
      {/if}
    </form>
  {/if}
</section>

<style>
  h2 {
    margin-bottom: var(--space-2);
  }
  h3 {
    font-size: var(--font-size-base);
    margin: var(--space-3) 0 var(--space-1) 0;
  }
  .settings-card {
    max-width: 32rem;
    padding: var(--space-4);
    margin-top: var(--space-4);
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  fieldset {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    border: none;
    padding: 0;
    margin: 0;
  }
  .success-text {
    color: var(--color-success);
  }
</style>
