#!/bin/sh

PIN_BIN=${PIN_ROOT}/pin
ANGORA_PATH=${HOME}/angora
OBJ_DIR=obj-intel64
#OBJ_DIR=obj-ia32
TOOL_PATH=${ANGORA_PATH}/pin_mode/mytool/${OBJ_DIR}/mytool.so

echo "${PIN_BIN} -t ${TOOL_PATH} -- "
