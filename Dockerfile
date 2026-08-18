# Build and runtime are separate stages so the shipped image carries a JRE and a jar,
# not Maven, a JDK and the whole dependency cache. It is the difference between an
# image with a compiler in it and one without.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build

# Dependencies resolve in their own layer, so editing a source file does not re-download
# the internet.
COPY pom.xml .
RUN mvn -B -q dependency:go-offline

COPY src ./src
RUN mvn -B -q package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app

# Runs as a non-root user. A gateway whose job is confining what an agent can reach has
# no business being root inside its own container.
RUN useradd --system --create-home --uid 10001 toolgate \
    && mkdir -p /var/lib/toolgate \
    && chown toolgate:toolgate /var/lib/toolgate

COPY --from=build /build/target/toolgate-*.jar /app/toolgate.jar

USER toolgate

# Pins, the audit trail and the approval queue live here. Mount a volume over it —
# without one, every restart re-approves every tool, which is the failure the pin file
# exists to prevent.
VOLUME ["/var/lib/toolgate"]

ENV TOOLGATE_PINS_FILE=/var/lib/toolgate/pins.json \
    TOOLGATE_AUDIT_FILE=/var/lib/toolgate/audit.jsonl \
    TOOLGATE_APPROVALS_FILE=/var/lib/toolgate/approvals.json

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/toolgate.jar"]
