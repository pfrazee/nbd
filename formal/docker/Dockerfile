# Tamarin and Maude in a container, so proofs run with bounded CPU and memory.
# Build and run from the repository root; see formal/README.md.
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      maude libgmp10 libffi8 libnuma1 python3 perl ca-certificates curl patchelf \
 && rm -rf /var/lib/apt/lists/*

# The release's Linux bottle for this architecture (arm64 or x86_64), with its
# Homebrew loader path replaced by the system's.
ARG TAMARIN=1.12.0
RUN arch=$(uname -m | sed 's/aarch64/arm64/') \
 && curl -fsSL -o /tmp/tamarin.tar.gz \
      "https://github.com/tamarin-prover/tamarin-prover/releases/download/${TAMARIN}/tamarin-prover-${TAMARIN}.${arch}_linux.bottle.tar.gz" \
 && tar -xzf /tmp/tamarin.tar.gz -C /opt \
 && bin=/opt/tamarin-prover/${TAMARIN}/bin/tamarin-prover \
 && patchelf --set-interpreter "$(ls /lib/ld-linux-*.so.* /lib64/ld-linux-*.so.* 2>/dev/null | head -1)" --remove-rpath "$bin" \
 && ln -s "$bin" /usr/local/bin/tamarin-prover \
 && rm /tmp/tamarin.tar.gz \
 && ulimit -n 65536 && tamarin-prover --version

# Tamarin prints formulas with Unicode symbols.
ENV LANG=C.UTF-8
# Tamarin fails to start Maude under some Docker hosts' very large open-file
# limits ("Too many open files"), so lower the limit before every command.
ENTRYPOINT ["/bin/sh", "-c", "ulimit -n 65536 && exec \"$@\"", "--"]
WORKDIR /formal
