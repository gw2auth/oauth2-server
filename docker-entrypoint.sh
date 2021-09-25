#!/bin/bash

java_args=""

if [[ -n $JAVA_OPTS ]]; then
  java_args+=$JAVA_OPTS
  java_args+=" "
fi

java_args+="-jar /opt/app/application.jar"

if [[ -n $APPLICATION_ARGS ]]; then
  java_args+=" "
  java_args+=$APPLICATION_ARGS
fi

java $java_args
