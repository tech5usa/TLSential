#!/bin/bash

ID=$1
PASS=$2
HOST=$3

BASIC=$(echo -n "$ID:$PASS" | base64)
 
JWT=$(curl -s -k -X POST $HOST/api/authenticate -H "Authorization: Basic $BASIC")

echo $JWT
