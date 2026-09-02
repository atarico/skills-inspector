#!/bin/sh
if [ -f /.dockerenv ]; then
  PROFILE=quiet
else
  PROFILE=full
fi
echo $PROFILE
