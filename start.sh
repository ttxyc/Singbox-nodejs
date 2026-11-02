#!/bin/bash
cd "$(dirname "$0")"
mkdir -p .tmp

export MALLOC_ARENA_MAX=2
export UV_THREADPOOL_SIZE=2
export NODE_NO_WARNINGS=1

while true; do
    node --max-old-space-size=80 --expose-gc index.js
    code=$?
    if [ $code -eq 0 ]; then
        echo "[INFO] index.js exited normally"
        break
    fi
    if [ $code -eq 130 ] || [ $code -eq 143 ]; then
        echo "[INFO] terminated by signal"
        break
    fi
    echo "[WARN] index.js exited with code $code, restarting in 5s..."
    sleep 5
done
