#!/bin/bash

llama-server \
    --model qwen3.5-9B-Q3_K_M.gguf \
    --alias "Qwen3" \
    --temp 0.6 \
    --top-p 0.95 \
    --top-k 20 \
    --min-p 0.00 \
    --port 8001 \
    --host 0.0.0.0 \
    --kv-unified \
    --cache-type-k q4_0 --cache-type-v q4_0 \
    --flash-attn on --fit on \
    --batch-size 4096 \
    --ubatch-size 1024 \
    --ctx-size 32768 \
    --threads 10 \
    --no-mmap