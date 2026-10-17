#!/usr/bin/env bash
test "$(tr -d '[:space:]' < answer.txt)" = "staging"
