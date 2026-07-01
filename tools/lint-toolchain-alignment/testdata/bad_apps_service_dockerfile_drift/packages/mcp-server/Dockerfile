FROM node:20-alpine AS base

WORKDIR /srv

# packages/*/Dockerfile* is now in scope (F247); this non-Go file
# proves the FROM-golang: filter skips it silently.
