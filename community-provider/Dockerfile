# syntax=docker/dockerfile:1
# Unmodified MIT-licensed community source. No project-developed Java provider.
FROM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS build
ADD --checksum=sha256:3936f2e016535aa3ea18b63ac739b632de303d411ccbf97449a0ca205739036b https://codeload.github.com/hqqw2h-lgtm/keycloak-services-social-wecom/tar.gz/a777528752f8b75edd1cf769297ef8c52d72678c /tmp/upstream.tar.gz
RUN mkdir /src && tar -xzf /tmp/upstream.tar.gz --strip-components=1 -C /src
WORKDIR /src
RUN mvn -B -ntp -Dgpg.skip=true -Dmaven.javadoc.skip=true package

FROM quay.io/keycloak/keycloak:26.6.4@sha256:0aae0de7fca85525f727d3354df17896092de8bb26ae4c12d89c77e5df8cbce4
LABEL org.opencontainers.image.source="https://github.com/hqqw2h-lgtm/keycloak-services-social-wecom" \
      org.opencontainers.image.revision="a777528752f8b75edd1cf769297ef8c52d72678c"
COPY --from=build --chown=keycloak:keycloak /src/target/keycloak-services-social-wecom-0.1.0.jar /opt/keycloak/providers/community-wecom.jar
COPY --from=build --chown=keycloak:keycloak /src/LICENSE /opt/keycloak/community-wecom-LICENSE
RUN /opt/keycloak/bin/kc.sh build --db=postgres --health-enabled=true --metrics-enabled=true
