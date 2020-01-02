#!/bin/bash
set -euo pipefail
php -S 0.0.0.0:1337 # lol, CORS doesn't like file:///
