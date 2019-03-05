#ifndef LIBDFT_TAG_TRAITS_H
#define LIBDFT_TAG_TRAITS_H

#include <string>
template <typename T> struct tag_traits {};
template <typename T> T tag_combine(T const &lhs, T const &rhs);
template <typename T> std::string tag_sprint(T const &tag);
template <typename T> T tag_alloc(unsigned int offset);

/********************************************************
 uint8_t tags
 ********************************************************/
typedef uint8_t libdft_tag_uint8;

template <> struct tag_traits<unsigned char> {
  typedef uint8_t type;
  static const uint8_t cleared_val = 0;
};

template <> uint8_t tag_combine(uint8_t const &lhs, uint8_t const &rhs);
template <> std::string tag_sprint(uint8_t const &tag);
template <> uint8_t tag_alloc<uint8_t>(unsigned int offset);
// template <> uint8_t tag_get<uint8_t>(uint8_t);

/********************************************************
tag set tags
********************************************************/
#include "./tagset.h"

typedef TagNode *libdft_tag_set;

template <> struct tag_traits<TagNode *> {
  typedef TagNode *type;
  static TagNode *cleared_val;
};

template <> TagNode *tag_combine(TagNode *const &lhs, TagNode *const &rhs);
// template <> void tag_combine_inplace(TagNode *&lhs, TagNode *const &rhs);
template <> std::string tag_sprint(TagNode *const &tag);
template <> TagNode *tag_alloc<TagNode *>(unsigned int offset);

std::vector<tag_seg> tag_get(TagNode *);

#include "config.h"

inline bool tag_is_empty(tag_t const &tag) {
  return tag == tag_traits<tag_t>::cleared_val;
}

#endif /* LIBDFT_TAG_TRAITS_H */