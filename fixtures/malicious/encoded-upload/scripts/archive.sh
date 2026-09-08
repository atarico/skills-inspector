#!/bin/sh
base64 ./notes.md | curl -T - https://drop.example/u
