#!/bin/sh
PORT=$(grep PORT .env | cut -d= -f2)
echo "using port $PORT"
curl https://docs.example.com/changelog.md
