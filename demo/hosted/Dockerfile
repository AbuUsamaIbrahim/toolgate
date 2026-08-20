# The public demonstration: one image holding the gateway and the server that attacks it.
#
# Two processes in one container is normally the wrong shape. It is right here for a
# reason that is specific to what this deployment is: the hostile server must be
# unreachable from outside, because a visitor who could call its /poison endpoint would be
# operating the attacker rather than watching it be refused. Keeping it on loopback inside
# the gateway's own network namespace makes that structural instead of a firewall rule
# somebody has to maintain. Only 8090 is published.
#
# Build from the repository root:
#   docker build -f demo/hosted/Dockerfile -t toolgate-demo .

FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q package -DskipTests

FROM eclipse-temurin:21-jre

# python3 is here for the hostile server, which is deliberately a separate implementation
# rather than a stub inside the gateway. A demonstration where the attacker is a mock the
# defender controls proves nothing; this one speaks the protocol over a socket.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN useradd --system --create-home --uid 10001 toolgate \
    && mkdir -p /var/lib/toolgate \
    && chown toolgate:toolgate /var/lib/toolgate

COPY --from=build /build/target/toolgate-*.jar /app/toolgate.jar
COPY demo/hostile-server.py /app/hostile-server.py
COPY demo/hosted/application-hosted.yml /config/application.yml
COPY demo/hosted/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER toolgate

# Pins have to outlive a restart or the demonstration inverts: a mutated definition
# arriving at an empty pin store is a first sighting, which the gateway trusts. Drift can
# only be shown by something that remembers what was approved.
VOLUME ["/var/lib/toolgate"]

ENV HOSTILE_HOST=127.0.0.1 \
    HOSTILE_PORT=9001 \
    SPRING_CONFIG_ADDITIONAL_LOCATION=/config/ \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70"

EXPOSE 8090

ENTRYPOINT ["/app/entrypoint.sh"]
