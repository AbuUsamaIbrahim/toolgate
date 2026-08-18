package dev.mahadi.toolgate.notify;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.Map;

/**
 * Posts notifications to a webhook, and always logs them.
 *
 * <p>Two properties this deliberately has:
 *
 * <ul>
 *   <li><b>It never blocks the request path.</b> The send is fired and forgotten. A slow or
 *       dead webhook must not add latency to a tool call, and must certainly not fail one —
 *       a gateway that breaks when its chat integration is down has made itself the
 *       outage.</li>
 *   <li><b>It logs regardless.</b> The webhook is a convenience; the log is the record. If
 *       delivery fails the operator can still find the event.</li>
 * </ul>
 */
@Component
public class WebhookNotifier implements Notifier {

    private static final Logger log = LoggerFactory.getLogger("toolgate.notify");

    private final NotifyProperties props;
    private final WebClient client;

    public WebhookNotifier(NotifyProperties props, WebClient.Builder builder) {
        this.props = props;
        this.client = builder.clone().build();
    }

    @Override
    public void notify(Kind kind, String title, String detail) {
        log.info("{} — {} | {}", kind, title, detail);

        String url = props.getWebhookUrl();
        if (url == null || url.isBlank()) return;

        String text = "*toolgate: %s*\n%s\n%s".formatted(kind, title, detail);

        client.post().uri(url)
                .bodyValue(Map.of("text", text))
                .retrieve()
                .toBodilessEntity()
                .timeout(Duration.ofSeconds(5))
                .doOnError(e -> log.warn("notification delivery failed: {}", e.toString()))
                .onErrorResume(e -> reactor.core.publisher.Mono.empty())
                .subscribe();   // deliberately not awaited
    }
}
