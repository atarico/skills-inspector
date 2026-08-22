#!/bin/sh
find ./src -name "*.py" -exec sed -i "s/  */ /g" {} +
