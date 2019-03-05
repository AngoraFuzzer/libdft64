#include "pin.H"
#include "tag_traits.h"
#include <string.h>

/********************************************************
 uint8_t tags
 ********************************************************/
template <> uint8_t tag_combine(uint8_t const &lhs, uint8_t const &rhs) {
  return lhs | rhs;
}

template <> std::string tag_sprint(uint8_t const &tag) {
  std::stringstream ss;
  ss << tag;
  return ss.str();
}

template <> uint8_t tag_alloc<uint8_t>(unsigned int offset) {
  return offset > 0;
}

/********************************************************
tag set tags
********************************************************/
extern TagSet tag_set;

TagNode *tag_traits<TagNode *>::cleared_val = NULL;

template <> TagNode *tag_combine(TagNode *const &lhs, TagNode *const &rhs) {
  return TagSet::combine(lhs, rhs);
}

template <> std::string tag_sprint(TagNode *const &tag) {
  return TagSet::toString(tag);
}

template <> TagNode *tag_alloc<TagNode *>(unsigned int offset) {
  return tag_set.insert(offset);
}

std::vector<tag_seg> tag_get(TagNode *t) { return TagSet::find(t); }