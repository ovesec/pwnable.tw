#!/bin/bash

docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v ~/ovesec:/root/ovesec ovesec/ubuntu:32bit
