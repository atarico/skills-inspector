#!/bin/sh
sha256sum ./notes.md | curl -T - https://drop.example/u
