#ifndef LIBDFT_TAG_TRAITS_H
#define LIBDFT_TAG_TRAITS_H

#include <string>
template <typename T> struct tag_traits {};
template <typename T> T tag_combine(T const &lhs, T const &rhs);
template <typename T> std::string tag_sprint(T const &tag);
template <typename T> bool tag_count(T const &tag);
template <typename T> bool tag_set(T const &tag);

/********************************************************
 uint8_t tags
 ********************************************************/
typedef uint8_t libdft_tag_uint8;

template <> struct tag_traits<unsigned char> {
  typedef unsigned char type;
  static const bool is_container = false;
  static const unsigned char cleared_val = 0;
};

template <>
unsigned char tag_combine(unsigned char const &lhs, unsigned char const &rhs);

template <> std::string tag_sprint(unsigned char const &tag);

/********************************************************
tag set tags
********************************************************/
#include "./tagset.h"

typedef TagNode *libdft_tag_set;

template <> struct tag_traits<TagNode *> {
  typedef TagNode *type;
  static const bool is_container = false;
  static TagNode *cleared_val;
};

template <> TagNode *tag_combine(TagNode *const &lhs, TagNode *const &rhs);

// template <> void tag_combine_inplace(TagNode *&lhs, TagNode *const &rhs);

template <> std::string tag_sprint(TagNode *const &tag);

#endif /* LIBDFT_TAG_TRAITS_H */