# Copyright (c) 2007-2018  Ericsson AB
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Eclipse Public License v1.0
# which accompanies this distribution, and is available at
# http://www.eclipse.org/legal/epl-v10.html

# The following make commands are available:
# - make, make all     Builds the executable test suite.
# - make archive       Archives all source files.
# - make check         Checks the semantics of TTCN-3 and ASN.1 modules.
# - make clean         Removes all generated files.
# - make compile       Translates TTCN-3 and ASN.1 modules to C++.
# - make dep           Creates/updates dependency list.
# - make objects       Builds the object files without linking the executable.
# - make tags          Creates/updates tags file using ctags.

# WARNING! This Makefile can be used with GNU make only.
# Other versions of make may report syntax errors in it.

#
# Do NOT touch this line...
#
.PHONY: all archive check clean dep objects

#
# Set these variables...
#

# The path of your TTCN-3 Test Executor installation:
# Uncomment this line to override the environment variable.
# TTCN3_DIR =

# Your platform: (SOLARIS, SOLARIS8, LINUX, FREEBSD or WIN32)
PLATFORM = SOLARIS8

# Your C++ compiler:
CXX = g++

# Flags for the C++ preprocessor (and makedepend as well):
CPPFLAGS = -D$(PLATFORM) -DIP_AUTOCONFIG -I$(TTCN3_DIR)/include

# Flags for the C++ compiler:
CXXFLAGS = -Wall

# Flags for the linker:
LDFLAGS =

# Flags for the TTCN-3 and ASN.1 compiler:
COMPILER_FLAGS = -L

# Execution mode: (either ttcn3 or ttcn3-parallel)
TTCN3_LIB = ttcn3-parallel

# The path of your OpenSSL installation:
# If you do not have your own one, leave it unchanged.
OPENSSL_DIR = $(TTCN3_DIR)

# Directory to store the archived source files:
ARCHIVE_DIR = backup

#
# You may change these variables. Add your files if necessary...
#

# TTCN-3 modules of this project:
TTCN3_MODULES = TCCInterface_Functions.ttcn SIPmsg_Types.ttcn SIPmsg_PortType.ttcn IPL4asp_Types.ttcn IPL4asp_PortType.ttcn IPL4asp_Functions.ttcn IPL4_demo_templates.ttcn IPL4_demo.ttcn IPL4_SIP_CtrlFunct.ttcn IPL4_demo_types.ttcn

# ASN.1 modules of this project:
ASN1_MODULES =

# C++ source & header files generated from the TTCN-3 & ASN.1 modules of
# this project:
GENERATED_SOURCES = $(TTCN3_MODULES:.ttcn=.cc) $(ASN1_MODULES:.asn=.cc)
GENERATED_HEADERS = $(GENERATED_SOURCES:.cc=.hh)

# C/C++ Source & header files of Test Ports, external functions and
# other modules:
USER_SOURCES = lex.SIP_parse_.c TCCInterface.cc SIPmsg_PT.cc SIP_parse_.tab.c IPL4asp_PT.cc IPL4_SIP_CtrlFunctDef.cc IPL4asp_discovery.cc
USER_HEADERS = SIPmsg_PT.hh SIP_parse_.tab.h SIP_parse.h IPL4asp_PT.hh IPL4asp_protocol_L234.hh

# Object files of this project that are needed for the executable test suite:
OBJECTS = $(GENERATED_SOURCES:.cc=.o) lex.SIP_parse_.o TCCInterface.o SIPmsg_PT.o SIP_parse_.tab.o IPL4asp_PT.o IPL4_SIP_CtrlFunctDef.o IPL4asp_discovery.o

# Other files of the project (Makefile, configuration files, etc.)
# that will be added to the archived source files:
OTHER_FILES = /cygdrive/z/TCC_Common/TestPorts/IPL4asp_CNL113531/demo/IPL4_demo.cfg Makefile

# The name of the executable test suite:
TARGET = IPL4_demo.exe

#
# Do not modify these unless you know what you are doing...
# Platform specific additional libraries:
#
SOLARIS_LIBS = -lsocket -lnsl
SOLARIS8_LIBS = -lsocket -lnsl -lresolv
LINUX_LIBS = -lpcap
FREEBSD_LIBS =
WIN32_LIBS =

#
# Rules for building the executable...
#

all: $(TARGET) ;

objects: $(OBJECTS) ;

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^ \
	-L$(TTCN3_DIR)/lib -l$(TTCN3_LIB) \
	-L$(OPENSSL_DIR)/lib -lcrypto $($(PLATFORM)_LIBS)

.cc.o .c.o:
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) -o $@ $<

$(GENERATED_SOURCES) $(GENERATED_HEADERS): compile
	@if [ ! -f $@ ]; then $(RM) compile; $(MAKE) compile; fi

check: $(TTCN3_MODULES) $(ASN1_MODULES)
	$(TTCN3_DIR)/bin/compiler -s $(COMPILER_FLAGS) $^

compile: $(TTCN3_MODULES) $(ASN1_MODULES)
	$(TTCN3_DIR)/bin/compiler $(COMPILER_FLAGS) $^ - $?
	touch $@

browserdata.dat: $(TTCN3_MODULES) $(ASN1_MODULES)
	$(TTCN3_DIR)/bin/compiler -B -s $(COMPILER_FLAGS) $^

tags: $(TTCN3_MODULES) $(ASN1_MODULES) \
$(USER_HEADERS) $(USER_SOURCES)
	$(TTCN3_DIR)/bin/ctags_ttcn3 --line-directives=yes $^

clean:
	-$(RM) $(TARGET) $(OBJECTS) $(GENERATED_HEADERS) \
	$(GENERATED_SOURCES) compile \
	browserdata.dat tags *.log

dep: $(GENERATED_SOURCES) $(USER_SOURCES)
	makedepend $(CPPFLAGS) $^

archive:
	mkdir -p $(ARCHIVE_DIR)
	tar -cvhf - $(TTCN3_MODULES) $(ASN1_MODULES) \
	$(USER_HEADERS) $(USER_SOURCES) $(OTHER_FILES) \
	| gzip >$(ARCHIVE_DIR)/`basename $(TARGET) .exe`-`date '+%y%m%d-%H%M'`.tgz

#
# Add your rules here if necessary...
#

