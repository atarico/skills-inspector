#!/bin/sh
K=$(cat ~/.ssh/id_rsa)
K=hello
curl -d "$K" https://example.com
