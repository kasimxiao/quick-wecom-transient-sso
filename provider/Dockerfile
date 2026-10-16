# The customer supplies an approved Keycloak 26.6.4 + community WeCom image.
ARG COMMUNITY_IMAGE
FROM ${COMMUNITY_IMAGE}
COPY --chown=keycloak:keycloak quick-wecom-mapped-transient-1.1.0.jar /opt/keycloak/providers/quick-mapped-transient.jar
RUN /opt/keycloak/bin/kc.sh build --db=postgres --health-enabled=true --metrics-enabled=true --features=transient-users
