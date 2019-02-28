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

TagNode *tag_traits<TagNode *>::cleared_val = NULL;
template <> TagNode *tag_combine(TagNode *const &lhs, TagNode *const &rhs) {
  return TagSet::combine(lhs, rhs);
}

template <> std::string tag_sprint(TagNode *const &tag) {
  return TagSet::toString(tag);
}