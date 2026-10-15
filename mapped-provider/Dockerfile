# Build the JAR with the pinned Maven image before this image build.
ARG COMMUNITY_IMAGE=quick-wecom-community:a777528-26.6.4
FROM ${COMMUNITY_IMAGE}
COPY --chown=keycloak:keycloak target/quick-wecom-mapped-transient-1.1.0.jar /opt/keycloak/providers/quick-mapped-transient.jar
RUN /opt/keycloak/bin/kc.sh build --db=postgres --health-enabled=true --metrics-enabled=true --features=transient-users
