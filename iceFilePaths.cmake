# This file is to add source files and include directories
# into variables so that it can be reused from different repositories
# in their Cmake based build system by including this file.
#
# Files specific to the repository such as test runner, platform tests
# are not added to the variables.

# Signaling library source files.
set( ICE_SOURCES
     "source/ice_api.c" )

# Signaling library Public Include directories.
set( ICE_INCLUDE_PUBLIC_DIRS
     "source/include" )

# Signaling library public include header files.
set( ICE_INCLUDE_PUBLIC_FILES
     "source/include/ice_api.h"
     "source/include/ice_data_types.h" )