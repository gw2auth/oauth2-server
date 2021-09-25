FROM adoptopenjdk/openjdk16:latest
RUN mkdir /opt/app
COPY docker-entrypoint.sh /opt/app
COPY target/oauth2-server.jar /opt/app/application.jar
ENTRYPOINT ["/opt/app/docker-entrypoint.sh"]