# Copyright (C) 2023 Tempesta Technologies, INC.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.

-include Makefile.local
CXX		:= g++
CFLAGS		:= -O2 -march=native -mtune=native -Wall \
		   -DL1DSZ=$(shell getconf LEVEL1_DCACHE_LINESIZE)
ifneq ($(SSL_INCLUDE),)
CFLAGS		:= $(CFLAGS) -I$(SSL_INCLUDE)
endif

LDFLAGS		:= -lpthread -lssl -lcrypto
ifneq ($(SSL_LIBDIR),)
LDFLAGS		:= -Wl,-rpath $(SSL_LIBDIR) -L $(SSL_LIBDIR) $(LDFLAGS)
endif

all : tls-perf

tls-perf: main.o
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CXX) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean: FORCE
	rm -f *.o* *~ tls-perf

FORCE:

