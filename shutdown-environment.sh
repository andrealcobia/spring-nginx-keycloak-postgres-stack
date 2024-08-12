#!/usr/bin/env bash

echo
echo "Starting the environment shutdown"
echo "================================="
docker-compose down -v

echo
echo "Removing containers"
echo "-------------------"
docker rmi service-app:1.0.0 postgres:16.3 nginx:1.25.4 quay.io/keycloak/keycloak:25.0.2

echo
echo "Environment shutdown successfully"
echo "================================="
echo
