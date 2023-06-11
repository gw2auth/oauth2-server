#!/bin/sh
container_id=$(docker run -d --rm -p 26257:26257 -p 8080:8080 cockroachdb/cockroach:v23.1.8 start-single-node --insecure)
sleep 5
echo "container started $container_id"

docker exec -it "$container_id" cockroach sql --execute "CREATE USER gw2auth_app; CREATE USER flyway;" --insecure
echo "users created"

echo "waiting for SIGINT"
( trap exit SIGINT ; read -r -d '' _ </dev/tty )
echo "received SIGINT, stopping container"
docker stop "$container_id"
echo "container stopped. bye"