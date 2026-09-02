#!/bin/sh
if [ -f ./build.conf ]; then
  PROFILE=quiet
else
  PROFILE=full
fi
echo $PROFILE
