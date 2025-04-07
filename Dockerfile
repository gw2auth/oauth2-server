FROM eclipse-temurin:24-alpine
RUN mkdir /opt/app
COPY docker-entrypoint.sh /opt/app/docker-entrypoint.sh
COPY target/oauth2-server.jar /opt/app/application.jar
RUN chmod +x /opt/app/docker-entrypoint.sh
ENTRYPOINT ["/opt/app/docker-entrypoint.sh"]