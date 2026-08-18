package dev.mahadi.toolgate.notify;

/**
 * Tells a human that the gateway is waiting on them.
 *
 * <p>Without this, a blocked call is indistinguishable from a broken one. The approval sits
 * in a queue nobody is watching, the agent fails, and the operator concludes the gateway is
 * unreliable — which is how a working control gets switched off.
 */
public interface Notifier {

    enum Kind {
        /** A call is blocked pending a human decision. */
        APPROVAL_REQUIRED,
        /** A tool definition changed and is being refused until reviewed. */
        DRIFT_DETECTED
    }

    void notify(Kind kind, String title, String detail);
}
