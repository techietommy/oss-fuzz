# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/askama-rs/askama.git askama
WORKDIR askama/fuzzing

# The current default toolchain used by OSS-Fuzz (1.81) is too old for askama v0.15,
# which needs at least 1.88.
ENV RUSTUP_TOOLCHAIN nightly-2025-07-04

COPY build.sh $SRC/
