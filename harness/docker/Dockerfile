# Verification image for CWEval-derived benchmark cases.
#
# CWEval's oracles are pytest files (the JS ones shell out to `node`), and many
# tasks invoke Unix tools (`ls`, tar, ...) and third-party libraries. Running
# them faithfully needs a Linux box with Python + Node + the CWEval dependency
# stack — that is exactly what this image provides. The harness mounts a single
# sandboxed case at /work and runs `pytest oracle`.
#
# Build once from harness/:  docker build -t securepatch-cweval docker/
FROM python:3.12-slim

# Node.js 20 + a toolchain for native node addons (sqlite3, argon2) and Unix
# utilities the oracles shell out to.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg build-essential \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Python libraries imported by the CWEval Python oracles.
RUN pip install --no-cache-dir \
        pytest \
        pycryptodome \
        pyyaml \
        wrapt_timeout_decorator \
        lxml \
        PyJWT \
        argon2-cffi

# JS libraries required by the CWEval JS tasks. Installed globally; NODE_PATH
# lets a mounted script's require() resolve them.
RUN npm install -g \
        xpath \
        sqlite3 \
        node-rsa \
        js-yaml \
        jsonwebtoken \
        jsdom \
        lodash \
        escape-html \
        argon2
ENV NODE_PATH=/usr/lib/node_modules

# Register the CWEval pytest markers so `-m functionality` / `-m security` do
# not warn, and default to quiet collection.
RUN printf '[pytest]\nmarkers =\n    functionality: functional correctness checks\n    security: exploit-resistance checks\n' > /etc/pytest.ini
ENV PYTEST_ADDOPTS="-c /etc/pytest.ini"

WORKDIR /work
