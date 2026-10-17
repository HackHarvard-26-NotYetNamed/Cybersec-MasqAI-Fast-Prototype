#!/usr/bin/env bash
set -euo pipefail
jdk="{{ROOT}}/opt/jdks/temurin-17.0.11"
mkdir -p "$jdk/bin"
printf '#!/usr/bin/env bash\necho "openjdk version \\"17.0.11\\" 2024-04-16"\n' > "$jdk/bin/java"
chmod +x "$jdk/bin/java"
