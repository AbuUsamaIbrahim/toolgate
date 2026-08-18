package dev.mahadi.toolgate.control;

import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Picks where fleet state lives, and builds the connection pool if there is one.
 *
 * <h2>Why there is no DataSource bean</h2>
 * Two attempts failed before this one, and both are worth recording. Spring Boot's JDBC
 * autoconfiguration builds a pool whenever a pooling library is on the classpath, without
 * checking that a URL was configured — so a gateway on a laptop, which wants no database
 * at all, failed to start with "failed to determine a suitable driver class". Excluding
 * that autoconfiguration and declaring a {@code DataSource} bean that returns null then
 * failed differently: the actuator's database health contributor sees the bean
 * <em>definition</em> and blows up on the null instance.
 *
 * <p>So the pool is not a bean. It is owned by the registry that uses it, created only
 * when an operator configures a URL, and closed with it. A component nothing else needs
 * does not have to be shared to be correct.
 */
@Configuration
public class FleetRegistryConfiguration {

    private static final Logger log = LoggerFactory.getLogger(FleetRegistryConfiguration.class);

    @Bean
    FleetRegistry fleetRegistry(ControlProperties props) {
        if (!props.databaseConfigured()) {
            log.warn("No database configured — fleet state is in memory. Run exactly one "
                    + "replica: with more, each holds part of the fleet and the coverage "
                    + "report contradicts itself between requests.");
            return new InMemoryFleetRegistry();
        }

        HikariDataSource pool = new HikariDataSource();
        pool.setJdbcUrl(props.getDatabaseUrl());
        pool.setUsername(props.getDatabaseUser());
        pool.setPassword(props.getDatabasePassword());
        // Small on purpose: this pool serves check-ins and the occasional coverage report,
        // not request-path traffic. Oversized pools on every replica are how a modest
        // service exhausts a database's connection limit.
        pool.setMaximumPoolSize(5);
        pool.setPoolName("toolgate-control");

        return new PostgresFleetRegistry(pool);
    }
}
