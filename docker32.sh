#!/bin/bash

docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v $(pwd):/root/ovesec xsec/xsec:i386
