import type { CredentialKind, RecoveryInventory } from "./domain.js";

export type RecoveryRoute = "verified_email" | "verified_telephone" | "recovery_code" | "linked_credential" | "provider_recovery" | "support_escalation";

export function recoveryRoutes(kind: CredentialKind, inventory: RecoveryInventory): RecoveryRoute[] {
  const routes: RecoveryRoute[] = [];
  if (inventory.verifiedEmail) routes.push("verified_email");
  if (inventory.verifiedTelephone) routes.push("verified_telephone");
  if (inventory.unusedRecoveryCodes > 0) routes.push("recovery_code");
  if (inventory.activeCredentials.some((candidate) => candidate !== kind)) routes.push("linked_credential");
  if (kind === "google" || kind === "apple") routes.push("provider_recovery");
  routes.push("support_escalation");
  return [...new Set(routes)];
}

export function canRemoveCredential(kind: CredentialKind, inventory: RecoveryInventory): boolean {
  const remainingCredentials = inventory.activeCredentials.filter((candidate) => candidate !== kind);
  return remainingCredentials.length > 0 || inventory.verifiedEmail || inventory.verifiedTelephone || inventory.unusedRecoveryCodes > 0;
}
