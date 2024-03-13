MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
SHELL := /usr/bin/env bash
.SHELLFLAGS := -uo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.SUFFIXES:

.PHONY: build
build: guestbook guestbook-linux-amd64

guestbook: main.go
	go build -o guestbook main.go

guestbook-linux-amd64: main.go
	GOOS=linux GOARCH=amd64 go build -o guestbook-linux-amd64 main.go
