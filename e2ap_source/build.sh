#!/bin/bash

# Variables
SRC_DIR="./lib"
HEADERS_DIR="./headers"
WRAPPER_C="wrapper.c"
OUTPUT_DIR="./output"
OUTPUT_LIB="libriclibe2ap.so"
OUTPUT_STATIC_LIB="libriclibe2ap.a"


# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Compiler and flags
CC=gcc
CFLAGS="-fPIC -I$HEADERS_DIR"  # Position-independent code for shared libraries
LDFLAGS="-shared"


# Step 1: Compile object files
OBJ_FILES=$(find "$SRC_DIR" -name "*.c" -exec basename {} .c \; | sed "s#^#$OUTPUT_DIR/#g" | sed "s/\$/\.o/g")
for src in $(find "$SRC_DIR" -name "*.c"); do
    obj="$OUTPUT_DIR/$(basename $src .c).o"
    $CC -c $CFLAGS -o $obj $src
done
$CC -c $CFLAGS -o "$OUTPUT_DIR/wrapper.o" $WRAPPER_C

$CC $LDFLAGS -o "$OUTPUT_DIR/$OUTPUT_LIB" $OBJ_FILES "$OUTPUT_DIR/wrapper.o"

ar rcs "$OUTPUT_DIR/$OUTPUT_STATIC_LIB" $OBJ_FILES "$OUTPUT_DIR/wrapper.o"


# Check if the build was successful
if [[ $? -eq 0 ]]; then
  echo "Build successful! Shared library created at $OUTPUT_DIR/$OUTPUT_LIB"
else
  echo "Build failed."
  exit 1
fi