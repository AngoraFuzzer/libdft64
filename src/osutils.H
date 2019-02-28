///
/// @file
/// \brief Utility functions with OS-specific implementations.
///
#ifndef __OSUTILS_H__
#define __OSUTILS_H__

#include <iostream>
#include <string>

#include <assert.h>
#include <libgen.h>
#include <limits.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <set>

#include "pin.H"
#include "libdft_api.h"


extern std::string filename;
extern std::set<int> fdset;

// Check whether the file needs to be tainted or not
inline int in_dtracker_whitelist(const std::string & fname) {
	LOG("in_dtracker_whitelist " + fname + "\n");
        if(fname.find(filename) != std::string::npos){
		return 0;
	}else{
		return 1;
	}
}



inline int path_isdir(const std::string & path) {
#if defined(TARGET_LINUX) || defined(TARGET_MAC)
	struct stat stats;
	return (stat(path.c_str(), &stats) == 0 && S_ISDIR(stats.st_mode));
#elif defined(TARGET_WINDOWS)
	assert(0);
	return -1;
#endif
}

inline int path_exists(const std::string & path) {
#if defined(TARGET_LINUX) || defined(TARGET_MAC)
	return (access(path.c_str(), F_OK) == 0);
#elif defined(TARGET_WINDOWS)
	assert(0);
	return -1;
#endif
}


///
/// @brief Resolves an open file descriptor to a filename.
///
/// Any symbolic links in the path are resolved. If an error occurs,
/// the respective error message is returned instead of the file path.
/// Because the function uses a static buffer, the file path may be
/// returned truncated ending with "...".
///
///	@param fd -- the file descriptor to be resolved.
/// @return A string representing the full path to the file.
std::string fdname(int fd);
#endif

/* vim: set noet ts=4 sts=4 sw=4 ai : */
