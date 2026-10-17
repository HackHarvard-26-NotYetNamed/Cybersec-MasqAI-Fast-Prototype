#!/usr/bin/env bash
test "$(tr -d '[:space:]' < answer.txt)" = "{{ROOT}}/opt/jdks/temurin-17.0.11/bin/java"
