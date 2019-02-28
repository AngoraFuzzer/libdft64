#include "pin.H"
#include "tag_traits.h"
#include <string.h>

template <>
unsigned char tag_combine(unsigned char const &lhs, unsigned char const &rhs) {
  return lhs | rhs;
}

template <> std::string tag_sprint(unsigned char const &tag) {
  std::stringstream ss;
  ss << tag;
  return ss.str();
}

template <> bool tag_count(unsigned char const &tag) { return tag > 0; }
