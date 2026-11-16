#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

mvn_cmd=${MAVEN_BIN:-mvn}
java_cmd=java
if [[ -n "${JAVA_HOME:-}" ]]; then
  java_cmd="$JAVA_HOME/bin/java"
fi
repo_args=()
if [[ -n "${MAVEN_LOCAL_REPO:-}" ]]; then
  repo_args+=("-Dmaven.repo.local=${MAVEN_LOCAL_REPO}")
fi
project=()
output=target
case "${1:-boot2}" in
  boot2) ;;
  boot3) project=(-f boot3/pom.xml); output=boot3/target ;;
  *) echo "Usage: $0 [boot2|boot3]" >&2; exit 2 ;;
esac
"$mvn_cmd" "${repo_args[@]}" "${project[@]}" -B -ntp -DskipTests test-compile dependency:build-classpath \
  -DincludeScope=test "-Dmdep.outputFile=$PWD/$output/interop-classpath"
key=$(node -e 'const c=require("node:crypto"); process.stdout.write(Buffer.concat([Buffer.from([1]),c.randomBytes(31)]).toString("base64url"));')
# Bind only to loopback and use a one-off test key supplied through an environment variable.
starter=${SM_CRYPTO_JAR:-$output/classes}
SM_CRYPTO_DEMO_KEY="$key" "$java_cmd" -cp "$output/test-classes:$starter:$(cat "$output/interop-classpath")" \
  io.github.mrhjr.smcrypto.example.DemoApplication >"$output/interop-server.log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
origin=http://127.0.0.1:18080
for _ in $(seq 1 40); do
  curl -fsS --noproxy 127.0.0.1 "$origin/crypto/public-key" >/dev/null 2>&1 && break
  if ! kill -0 "$server" 2>/dev/null; then cat "$output/interop-server.log"; exit 1; fi
  sleep 0.4
done
curl -fsS --noproxy 127.0.0.1 "$origin/crypto/public-key" >/dev/null
env -u NODE_USE_ENV_PROXY NO_PROXY=127.0.0.1 npm --prefix frontend run interop -- "$origin" /demo/echo
env -u NODE_USE_ENV_PROXY NO_PROXY=127.0.0.1 node --input-type=module <<'JS'
import assert from 'node:assert/strict';
import { createCryptoClient } from './frontend/client.js';

const client = createCryptoClient({ origin: 'http://127.0.0.1:18080', allowInsecureLoopback: true });
const body = { message: '验证加密业务错误' };
assert.deepEqual(await client.post('/demo/reject', body), { status: 422, ok: false, data: body });
console.log('Authenticated non-2xx business response: OK');

const origin = 'http://127.0.0.1:18080';
const plaintextPost = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
const protectedPost = await fetch(origin + '/demo/echo', plaintextPost);
assert.equal(protectedPost.status, 400);
const excludedPost = await fetch(origin + '/demo/plain', plaintextPost);
assert.equal(excludedPost.status, 200);
assert.deepEqual(await excludedPost.json(), body);
const ordinaryGet = await fetch(origin + '/demo/plain');
assert.equal(ordinaryGet.status, 200);
const getBody = await ordinaryGet.json();
assert.ok(!('ciphertext' in getBody));
const prefixPost = await fetch(origin + '/demo/public/echo', plaintextPost);
assert.equal(prefixPost.status, 200);
assert.deepEqual(await prefixPost.json(), body);
const sameLetterPrefix = await fetch(origin + '/demo/publicity', plaintextPost);
assert.equal(sameLetterPrefix.status, 400);
console.log('Default POST protection, exact and prefix exemptions, boundary check, and unchanged GET: OK');
JS
