<!--
SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Building and contributing

Use Linux amd64 or arm64, Python 3.12, Node.js 24, npm, and Make. Build on the
architecture that will run the executable. A build requires internet access to
install dependencies from the committed Python and npm lockfiles. The resulting
binary uses the build host's glibc baseline; build on an older compatible Linux
host when supporting older distributions.

```bash
make setup
. .venv/bin/activate
make build
```

`make build` compiles and validates the report application, freezes the collection
CLI, checks startup and catalog discovery without contacting a target, and writes:

```text
dist/<amd64|arm64>/
  nvdebug
  config/Telemetry_Catalog_v<catalog-version>.xlsx
  dut_config.yaml
  tool_config.yaml
  README.md
  CONTRIBUTING.md
  release-notes.txt
  License.txt
  Third-party-licenses.md
  nvdebug-<version>-linux-<amd64|arm64>.tar.gz
  SHA256SUMS
```

The archive contains the same executable, catalog, configuration, and documentation
inside a versioned directory. The two YAML files are copied from the checkout's
`default_config/` directory. Edit these copies for binary runs; the catalog is
available separately in `config/`. The binary also embeds the catalog, default
configuration, and validated report application for standalone use.

`ipmitool` and `sshpass` remain optional system dependencies for collection paths
that use them. Verify all loose files and the archive with `sha256sum -c SHA256SUMS`
from `dist/amd64/` or `dist/arm64/`. Each architecture has its own output directory,
so builds can coexist. Existing output for the selected architecture is preserved;
for another build use
`python -I scripts/build_binary.py --output /path/to/new-output` after building the
report application.

To run from source after setup:

```bash
make build-report-app
python -m src.tool.main --help
python -m src.tool.main list-baseboards
```

Report changes should pass `make report-app-ci`, which audits dependencies, lints,
tests, and builds the application. Run `make audit-report-app` for a dependency
audit alone. Binary builds validate that report assets match the source tree.
Rebuild them whenever report source changes. Generated
assets, virtual environments, and binary build products do not belong in commits.

Run and validate these scripts on your own Linux build hosts or runners for each
architecture you intend to support. The resulting executable and archives stay
on your build host. `requirements.txt` includes all Python runtime and build
dependencies; npm installs the report dependencies from its separate lockfile.

Fork [NVIDIA/open-nvdebug](https://github.com/NVIDIA/open-nvdebug), make a focused
change, validate it, and open a pull request. Use synthetic fixtures for tests;
never include credentials, real collection output, or private service details.

#### Signing Your Work

* We require that all contributors "sign-off" on their commits. This certifies that the contribution is your original work, or you have rights to submit it under the same license, or a compatible license.

  * Any contribution which contains commits that are not Signed-Off will not be accepted.

* To sign off on a commit you simply use the `--signoff` (or `-s`) option when committing your changes:
  ```bash
  $ git commit -s -m "Add cool feature."
  ```
  This will append the following to your commit message:
  ```text
  Signed-off-by: Your Name <your@email.com>
  ```

* Full text of the DCO:

  ```text
    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
    1 Letterman Drive
    Suite D4700
    San Francisco, CA, 94129

    Everyone is permitted to copy and distribute verbatim copies of this license document, but changing it is not allowed.
  ```

  ```text
    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I have the right to submit it under the open source license indicated in the file; or

    (b) The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open source license and I have the right under that license to submit that work with modifications, whether created in whole or in part by me, under the same open source license (unless I am permitted to submit under a different license), as indicated in the file; or

    (c) The contribution was provided directly to me by some other person who certified (a), (b) or (c) and I have not modified it.

    (d) I understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information I submit with it, including my sign-off) is maintained indefinitely and may be redistributed consistent with this project or the open source license(s) involved.
  ```
