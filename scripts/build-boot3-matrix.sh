#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

mvn_cmd=${MAVEN_BIN:-mvn}
repo_args=()
if [[ -n "${MAVEN_LOCAL_REPO:-}" ]]; then
  repo_args+=("-Dmaven.repo.local=${MAVEN_LOCAL_REPO}")
fi
version=0.2.0
artifact=sm-crypto-spring-boot3-starter
mkdir -p dist/boot3
for v in 17 21; do
  name="JDK${v}_HOME"
  jdk=${!name:-}
  if [[ ! -x "$jdk/bin/javac" || ! -x "$jdk/bin/java" ]]; then
    echo "Set $name to a JDK $v installation." >&2
    exit 1
  fi
  compiler=$("$jdk/bin/javac" -version 2>&1)
  [[ "$compiler" == "javac $v".* ]] || { echo "Wrong JDK: $compiler" >&2; exit 1; }
  printf '\n== Boot 3 / JDK %s (%s) ==\n' "$v" "$compiler"
  JAVA_HOME="$jdk" PATH="$jdk/bin:$PATH" "$mvn_cmd" \
    "${repo_args[@]}" -B -ntp -f boot3/pom.xml "-Dmaven.compiler.release=$v" clean verify
  cp "boot3/target/$artifact-$version.jar" "dist/boot3/$artifact-$version-jdk$v.jar"
done
(cd dist/boot3 && sha256sum "$artifact"-*-jdk*.jar > SHA256SUMS)
