#!/bin/sh

java_args=""

if [ -n "$JAVA_OPTS" ]; then
  java_args="${JAVA_OPTS} "
fi

java_args="${java_args}-jar /opt/app/application.jar"

if [ -n "$APPLICATION_ARGS" ]; then
  java_args="${java_args} ${APPLICATION_ARGS}"
fi

exec java $java_args
