# Copyright 2017 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get -y update \
	&& DEBIAN_FRONTEND=noninteractive \
			apt-get install -y -q --no-install-recommends \
				gdb \
				libdbus-1-dev \
				libboost-dev \
				pkg-config \
				libtool \
				autoconf \
				autoconf-archive \
				automake

COPY build.sh *.options run_tests.sh $SRC/

RUN git clone --depth 1 https://github.com/openthread/wpantund

WORKDIR wpantund
