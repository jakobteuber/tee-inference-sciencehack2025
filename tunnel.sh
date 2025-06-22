#!/usr/bin/env bash
ssh -f -N -J avax -p 10024 -L 5050:localhost:5050 root@localhost
