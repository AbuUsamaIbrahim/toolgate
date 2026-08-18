package dev.mahadi.toolgate;

import dev.mahadi.toolgate.cli.BundleTool;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.util.Arrays;

@SpringBootApplication
@ConfigurationPropertiesScan
public class ToolgateApplication {

    /**
     * One jar, two jobs: run the gateway, or work with policy bundles.
     *
     * <p>Dispatching on the first argument rather than shipping a second artifact is a
     * deliberate ergonomic choice. Whoever signs a bundle is on a release machine or in CI
     * and needs the same version of the code that will verify it — two artifacts is two
     * chances for those to drift apart.
     *
     * <p>The handoff happens before Spring starts. There is no reason to boot a web server
     * to produce a file, and doing so would mean the signing tool needed valid gateway
     * configuration to run at all.
     */
    public static void main(String[] args) {
        if (args.length > 0 && "bundle".equals(args[0])) {
            try {
                BundleTool.main(Arrays.copyOfRange(args, 1, args.length));
            } catch (Exception e) {
                System.err.println("bundle: " + e.getMessage());
                System.exit(1);
            }
            return;
        }
        SpringApplication.run(ToolgateApplication.class, args);
    }
}
