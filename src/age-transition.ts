export type SupervisingPartyKind = "guardian" | "institution";

export interface SupervisingLink {
  id: string;
  kind: SupervisingPartyKind;
  status: "active" | "ended";
  permissions: string[];
}

export interface IndependenceTransition {
  userId: string;
  jurisdiction: string;
  eligibleAt: Date;
  ownContactVerified: boolean;
  identityRequirementSatisfied: boolean;
  adultTermsAccepted: boolean;
  independentRecoveryConfigured: boolean;
  dataReviewCompleted: boolean;
}

export const transitionReady = (transition: IndependenceTransition) =>
  transition.ownContactVerified &&
  transition.identityRequirementSatisfied &&
  transition.adultTermsAccepted &&
  transition.independentRecoveryConfigured &&
  transition.dataReviewCompleted;

export function endGuardianMonitoring(links: SupervisingLink[], transition: IndependenceTransition): SupervisingLink[] {
  if (!transitionReady(transition)) throw new Error("The independence transition is not complete.");
  return links.map((link) => link.kind === "guardian" ? { ...link, status: "ended", permissions: [] } : link);
}
