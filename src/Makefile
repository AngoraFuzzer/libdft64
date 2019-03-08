#
# NSL DFT lib (libdft)
#
# Columbia University, Department of Computer Science
# Network Security Lab
#
# Vasileios P. Kemerlis (vpk@cs.columbia.edu)
#
# variable definitions

TARGET ?= intel64

# If the tool is built out of the kit, PIN_ROOT must be specified in the make invocation and point to the kit root.
ifdef PIN_ROOT
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
else
CONFIG_ROOT := ../Config
endif

include $(CONFIG_ROOT)/makefile.config
include makefile.rules
include $(TOOLS_ROOT)/Config/makefile.default.rules
