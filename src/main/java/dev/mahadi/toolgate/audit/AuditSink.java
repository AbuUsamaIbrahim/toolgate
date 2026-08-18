package dev.mahadi.toolgate.audit;

/**
 * Somewhere an audit entry goes.
 *
 * <p>There is more than one, because the file on disk and the company's SIEM answer
 * different questions. The file is what an engineer greps at 2am on the machine in front of
 * them; the SIEM is what survives that machine being reimaged, and the only copy the person
 * being audited cannot edit.
 *
 * <p>Implementations must be cheap and must not throw for transient problems — an export
 * failure is not a reason to fail a tool call. The one exception is a deployment that has
 * explicitly asked to fail closed on an unwritable trail, which is what
 * {@link AuditWriteException} is for.
 */
public interface AuditSink {

    void append(AuditLog.Entry entry);

    /** Raised only when the deployment has chosen "no record" to mean "do not proceed". */
    class AuditWriteException extends RuntimeException {
        public AuditWriteException(String message, Throwable cause) { super(message, cause); }
    }
}
