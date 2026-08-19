package dev.mahadi.toolgate.api;

import dev.mahadi.toolgate.audit.AuditLog;

/** Events the dashboard SSE stream can carry. */
public sealed interface DashboardEvent {

    /** A new audit entry was recorded (any outcome except ALLOWED). */
    record AuditEntryAdded(AuditLog.Entry entry) implements DashboardEvent {}

    /** An approval was requested, granted, or denied. */
    record ApprovalsChanged() implements DashboardEvent {}

    /** Drift was detected or cleared. */
    record DriftChanged() implements DashboardEvent {}
}
