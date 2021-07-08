#!/bin/bash

# Determine machine type
unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     machine=linux;;
    Darwin*)    machine=darwin;;
    *)          machine="unknown"
esac

# Create a temp diretory to build within
rm -rf tmp
mkdir tmp
cd tmp

# Generate the static library file
../configure
make 'src/processor/libbugsnag_stackwalk_wrapper.a'

# Collect all object files into one directory
mkdir object_files
find . -name "*.o" -exec cp '{}' ./object_files \;
cd object_files
# Remove redundant object files
rm x86_format.o path_helper.o stackwalk_common.o stack_frame_cpu.o stackwalker_address_list.o
cd ..

# Generate the shared object file
g++ -shared -o ../build/${machine}/libbugsnag_stackwalk_wrapper.so `find ./object_files -iname "*.o"`

# Cleanup the temp directory
cd ..
rm -rf tmp
