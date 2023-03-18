#!/bin/sh
docker run -it --rm -p 5433:5432 -e POSTGRES_PASSWORD=postgres postgres:13.4