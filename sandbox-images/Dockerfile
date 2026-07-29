FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ARG DEBIAN_MIRROR=https://deb.debian.org/debian
ARG DEBIAN_SECURITY_MIRROR=https://deb.debian.org/debian-security
ARG MAVEN_VERSION=3.9.11
ARG MAVEN_SHA512=bcfe4fe305c962ace56ac7b5fc7a08b87d5abd8b7e89027ab251069faebee516b0ded8961445d6d91ec1985dfe30f8153268843c89aa392733d1a3ec956c9978
ARG GRADLE_VERSION=8.14.3
ARG GRADLE_SHA256=bd71102213493060956ec229d946beee57158dbd89d0e62b91bca0fa2c5f3531
ARG SEMGREP_VERSION=1.130.0
ARG PYDANTIC_VERSION=2.12.5
ARG PYYAML_VERSION=6.0.3
ARG ASM_VERSION=9.8
ARG ASM_SHA256=876eab6a83daecad5ca67eb9fcabb063c97b5aeb8cf1fca7a989ecde17522051
ARG CFR_VERSION=0.152
ARG CFR_SHA256=f686e8f3ded377d7bc87d216a90e9e9512df4156e75b06c655a16648ae8765b2

RUN sed -i \
        -e "s|http://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
        -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install --yes --no-install-recommends \
        ca-certificates \
        curl \
        openjdk-17-jdk-headless \
        unzip \
    && rm -rf /var/lib/apt/lists/* \
    && java_home="$(dirname "$(dirname "$(readlink -f /usr/bin/java)")")" \
    && mkdir -p /opt/java \
    && ln -s "${java_home}" /opt/java/openjdk

RUN curl --fail --location --silent --show-error \
        "https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz" \
        --output /tmp/apache-maven.tar.gz \
    && echo "${MAVEN_SHA512}  /tmp/apache-maven.tar.gz" | sha512sum --check --strict \
    && mkdir -p /opt/maven \
    && tar --extract --gzip --file /tmp/apache-maven.tar.gz --directory /opt/maven \
    && ln -s "/opt/maven/apache-maven-${MAVEN_VERSION}" /opt/maven/current \
    && rm /tmp/apache-maven.tar.gz

RUN curl --fail --location --silent --show-error \
        --retry 5 --retry-all-errors --connect-timeout 30 \
        "https://downloads.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
        --output /tmp/gradle.zip \
    && echo "${GRADLE_SHA256}  /tmp/gradle.zip" | sha256sum --check --strict \
    && mkdir -p /opt/gradle \
    && unzip -q /tmp/gradle.zip -d /opt/gradle \
    && ln -s "/opt/gradle/gradle-${GRADLE_VERSION}" /opt/gradle/current \
    && rm /tmp/gradle.zip

RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install --yes --no-install-recommends \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

RUN uv pip install --system --no-cache \
    "semgrep==${SEMGREP_VERSION}" \
    "setuptools==80.9.0" \
    "pydantic==${PYDANTIC_VERSION}" \
    "pyyaml==${PYYAML_VERSION}"

RUN mkdir -p /opt/cairn/tools \
    && curl --fail --location --silent --show-error \
        "https://repo.maven.apache.org/maven2/org/ow2/asm/asm/${ASM_VERSION}/asm-${ASM_VERSION}.jar" \
        --output "/opt/cairn/tools/asm-${ASM_VERSION}.jar" \
    && echo "${ASM_SHA256}  /opt/cairn/tools/asm-${ASM_VERSION}.jar" \
        | sha256sum --check --strict \
    && curl --fail --location --silent --show-error \
        "https://repo.maven.apache.org/maven2/org/benf/cfr/${CFR_VERSION}/cfr-${CFR_VERSION}.jar" \
        --output "/opt/cairn/tools/cfr-${CFR_VERSION}.jar" \
    && echo "${CFR_SHA256}  /opt/cairn/tools/cfr-${CFR_VERSION}.jar" \
        | sha256sum --check --strict

COPY ./sandbox-images/java/dev/cairn/bytecode/BytecodeIndexer.java \
    /tmp/cairn-bytecode-helper/dev/cairn/bytecode/BytecodeIndexer.java
RUN mkdir -p /tmp/cairn-bytecode-helper/classes \
    && javac \
        --release 17 \
        -encoding UTF-8 \
        -cp "/opt/cairn/tools/asm-${ASM_VERSION}.jar" \
        -d /tmp/cairn-bytecode-helper/classes \
        /tmp/cairn-bytecode-helper/dev/cairn/bytecode/BytecodeIndexer.java \
    && jar --create \
        --file /opt/cairn/tools/cairn-bytecode-indexer.jar \
        --main-class dev.cairn.bytecode.BytecodeIndexer \
        -C /tmp/cairn-bytecode-helper/classes . \
    && rm -rf /tmp/cairn-bytecode-helper \
    && chmod 0444 /opt/cairn/tools/*.jar

RUN groupadd --gid 65532 sandbox \
    && useradd \
        --uid 65532 \
        --gid 65532 \
        --no-create-home \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        sandbox \
    && mkdir -p /opt/cairn/bin /work/source /work/scratch /work/output \
    && chown -R 65532:65532 /work/scratch /work/output

COPY ./sandbox-images/runner.py /opt/cairn/bin/cairn-template-runner
COPY ./sandbox-images/normalize_permissions.py /opt/cairn/bin/normalize-workspace-permissions
COPY ./sandbox-images/rules/semgrep /opt/cairn/rules/semgrep
COPY ./sandbox-images/toolchain.json /opt/cairn/toolchain.json
COPY ./cairn/src/cairn/__init__.py /opt/cairn/lib/cairn/__init__.py
COPY ./cairn/src/cairn/analysis /opt/cairn/lib/cairn/analysis
RUN chmod 0555 \
        /opt/cairn/bin/cairn-template-runner \
        /opt/cairn/bin/normalize-workspace-permissions \
    && ln -s cairn-template-runner /opt/cairn/bin/run-analysis \
    && ln -s cairn-template-runner /opt/cairn/bin/run-build \
    && ln -s cairn-template-runner /opt/cairn/bin/run-validation

USER 65532:65532
WORKDIR /work/source

ENV JAVA_HOME=/opt/java/openjdk \
    PATH=/opt/maven/current/bin:/opt/gradle/current/bin:${PATH} \
    PYTHONPATH=/opt/cairn/lib

ENTRYPOINT []
CMD ["/opt/cairn/bin/run-analysis"]
