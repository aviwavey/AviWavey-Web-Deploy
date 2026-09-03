export type SecurityEventType =
  | "authentication.failed"
  | "authentication.succeeded"
  | "credential.linked"
  | "credential.revoked"
  | "recovery.started"
  | "recovery.completed"
  | "session.revoked"
  | "profile.completed";

export interface SecurityEvent {
  id: string;
  type: SecurityEventType;
  occurredAt: string;
  userId?: string;
  sessionId?: string;
  product?: "avi" | "aura";
  context: Record<string, string | number | boolean | null>;
}

/** Sentinel Guard consumes these events; it does not own the identity record. */
export interface SentinelGuardSink {
  publish(event: SecurityEvent): Promise<void>;
}

/** GeoSphere Grid contributes context; location alone never authenticates a user. */
export interface GeoSphereRiskContext {
  risk: "low" | "medium" | "high";
  impossibleTravelSuspected: boolean;
  declaredTravelActive: boolean;
  countryCode?: string;
  regionCode?: string;
}
