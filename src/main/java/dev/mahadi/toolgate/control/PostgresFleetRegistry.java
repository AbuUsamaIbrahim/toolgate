package dev.mahadi.toolgate.control;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.annotation.PreDestroy;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Fleet state in Postgres, so the control plane can have more than one replica.
 *
 * <p>The in-memory version is correct and forces {@code replicas: 1}. With two pods behind
 * one Service, each check-in lands on whichever pod the kernel picked, so each holds a
 * fraction of the fleet and the coverage report contradicts itself between requests. A
 * report claiming machines are unmonitored when they are not is worse than none, because
 * people act on it once and then stop believing it.
 *
 * <p>Plain JDBC rather than JPA. This is two tables and four statements; an ORM would
 * bring a mapping layer, a session lifecycle and a migration framework to hide SQL that
 * fits on a screen and that an auditor might reasonably want to read.
 *
 * <h2>The upsert is the whole design</h2>
 * Several pods may receive check-ins from the same machine concurrently, so the write has
 * to be safe under races without a transaction spanning a read and a write. {@code INSERT
 * … ON CONFLICT DO UPDATE} makes it one atomic statement, and {@code first_seen} is
 * deliberately left alone on conflict — "installed since" is a fact about the past that a
 * later check-in must not overwrite.
 */
public class PostgresFleetRegistry implements FleetRegistry {

    private static final Logger log = LoggerFactory.getLogger(PostgresFleetRegistry.class);

    private final HikariDataSource pool;
    private final JdbcClient db;

    public PostgresFleetRegistry(HikariDataSource pool) {
        this.pool = pool;
        this.db = JdbcClient.create(pool);
        migrate();
    }

    /** The pool is not shared with anything, so it is closed with the thing that owns it. */
    @PreDestroy
    void close() {
        pool.close();
    }

    /**
     * Creates the schema if it is absent.
     *
     * <p>Adequate for one table that has never changed shape. The moment it needs a second
     * version this should become Flyway or Liquibase — hand-rolled migration is fine until
     * it has to be ordered, and then it is suddenly not.
     */
    private void migrate() {
        db.sql("""
                CREATE TABLE IF NOT EXISTS fleet_member (
                    subject         TEXT        NOT NULL,
                    instance_id     TEXT        NOT NULL,
                    version         TEXT        NOT NULL,
                    bundle_sequence BIGINT      NOT NULL,
                    bundle_health   TEXT        NOT NULL,
                    first_seen      TIMESTAMPTZ NOT NULL,
                    last_seen       TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (subject, instance_id)
                )
                """).update();
        log.info("Fleet registry backed by Postgres");
    }

    @Override
    public Member checkIn(String subject, String instanceId, String version,
                          long bundleSequence, String bundleHealth) {
        Instant now = Instant.now();

        db.sql("""
                INSERT INTO fleet_member
                    (subject, instance_id, version, bundle_sequence, bundle_health,
                     first_seen, last_seen)
                VALUES (:subject, :instance, :version, :sequence, :health, :now, :now)
                ON CONFLICT (subject, instance_id) DO UPDATE SET
                    version         = EXCLUDED.version,
                    bundle_sequence = EXCLUDED.bundle_sequence,
                    bundle_health   = EXCLUDED.bundle_health,
                    last_seen       = EXCLUDED.last_seen
                """)
                .param("subject", subject)
                .param("instance", instanceId)
                .param("version", version)
                .param("sequence", bundleSequence)
                .param("health", bundleHealth)
                .param("now", Timestamp.from(now))
                .update();

        return db.sql("""
                        SELECT * FROM fleet_member
                        WHERE subject = :subject AND instance_id = :instance
                        """)
                .param("subject", subject)
                .param("instance", instanceId)
                .query(PostgresFleetRegistry::toMember)
                .single();
    }

    @Override
    public List<FleetView> view(long publishedSequence, Duration silentAfter) {
        Instant now = Instant.now();
        // Ordering is applied in Java rather than SQL so that every implementation sorts
        // identically — the rule lives in one place and cannot drift between backends.
        return db.sql("SELECT * FROM fleet_member")
                .query(PostgresFleetRegistry::toMember)
                .list().stream()
                .map(m -> new FleetView(m,
                        FleetRegistry.statusOf(m, publishedSequence, silentAfter, now),
                        Duration.between(m.lastSeen(), now)))
                .sorted(FleetRegistry.worstFirst())
                .toList();
    }

    @Override
    public int size() {
        return db.sql("SELECT count(*) FROM fleet_member").query(Integer.class).single();
    }

    @Override
    public int forget(Duration olderThan) {
        return db.sql("DELETE FROM fleet_member WHERE last_seen < :cutoff")
                .param("cutoff", Timestamp.from(Instant.now().minus(olderThan)))
                .update();
    }

    private static Member toMember(java.sql.ResultSet rs, int row) throws java.sql.SQLException {
        return new Member(
                rs.getString("subject"),
                rs.getString("instance_id"),
                rs.getString("version"),
                rs.getLong("bundle_sequence"),
                rs.getString("bundle_health"),
                rs.getTimestamp("first_seen").toInstant(),
                rs.getTimestamp("last_seen").toInstant());
    }
}
