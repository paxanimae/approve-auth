import type { RevokePolicyAction } from "./types";

// Shared source of the "click-to-define" revocation-policy choices --
// both RevocationPolicyDialog.svelte (per-application overrides) and
// Settings.svelte (the deployment-wide default, inlined directly on
// the page) render the exact same four <select> options from here,
// so the choices can never drift between the two places.
export const revokePolicyOptions: { value: RevokePolicyAction; label: string }[] = [
  { value: "off", label: "Off" },
  { value: "warn", label: "Warn (log only)" },
  { value: "flag_for_review", label: "Flag for review" },
  { value: "revoke", label: "Revoke access" },
];
