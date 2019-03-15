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
#include "./bdd_tag.h"

typedef lb_type libdft_bdd_tag;

template <> struct tag_traits<lb_type> {
  typedef lb_type type;
  static lb_type cleared_val;
};

template <> lb_type tag_combine(lb_type const &lhs, lb_type const &rhs);
// template <> void tag_combine_inplace(lb_type &lhs, lb_type const &rhs);
template <> std::string tag_sprint(lb_type const &tag);
template <> lb_type tag_alloc<lb_type>(unsigned int offset);

std::vector<tag_seg> tag_get(lb_type);

/********************************************************
others
********************************************************/
#if !defined(LIBDFT_TAG_TYPE)
#define LIBDFT_TAG_TYPE libdft_bdd_tag
#endif
typedef LIBDFT_TAG_TYPE tag_t;

inline bool tag_is_empty(tag_t const &tag) {
  return tag == tag_traits<tag_t>::cleared_val;
}

#endif /* LIBDFT_TAG_TRAITS_H */