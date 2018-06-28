#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
#  build_hardened_fragment.sh - Generate a config fragment from an .rst
#  file for the specified level.
#
#  Copyright 2018 Salvatore Mesoraca <s.mesoraca16@gmail.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2 as
#  published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the GNU General Public License for more details.

usage() {
	echo "Usage: $0 <level> <file.rst>" >&2
	echo "Level must be one of: low, medium, high, extreme." >&2
	exit 1
}

if [ "$#" -ne 2 ]; then
	usage
fi

LEVEL="$(echo $1 | tr [A-Z] [a-z])"
INPUT="$2"

if [ "$LEVEL" != "low" ] && \
   [ "$LEVEL" != "medium" ] && \
   [ "$LEVEL" != "high" ] && \
   [ "$LEVEL" != "extreme" ]; then
	usage
fi

if ! [ -f "$INPUT" ]; then
	usage
fi

if [ "$LEVEL" = "medium" ]; then
	LEVEL="(low|medium)"
elif [ "$LEVEL" = "high" ]; then
	LEVEL="(low|medium|high)"
elif [ "$LEVEL" = "extreme" ]; then
	LEVEL="(low|medium|high|extreme)"
fi

egrep -B3 -i "^\*\*Negative side effects level:\*\* $LEVEL$" "$INPUT" | \
grep "^CONFIG_" | \
sed 's/^\(.*\)=[nN]/# \1 is not set/'

exit 0
