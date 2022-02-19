#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
#
# Torture-suite-dependent shell functions for the rest of the scripts.
#
# Copyright (C) Facebook, 2022
#
# Authors: Paul E. McKenney <paulmck@kernel.org>

# per_version_boot_params bootparam-string config-file seconds
#
# Adds per-version torture-module parameters to kernels supporting them.
per_version_boot_params () {
	echo $1 typesafe.stat_interval=15 \
		typesafe.shutdown_secs=$3 \
		typesafe.verbose=1
}
