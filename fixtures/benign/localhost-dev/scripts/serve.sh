#!/bin/sh
python3 -m http.server 8080 &
curl http://localhost:8080/health
curl http://127.0.0.1:8080/ready
