#ifndef LIBDFT_TAG_TRAITS_H
#define LIBDFT_TAG_TRAITS_H

#include <string>
template <typename T> struct tag_traits {};
template <typename T> T tag_combine(T const &lhs, T const &rhs);
template <typename T> std::string tag_sprint(T const &tag);
template <typename T> bool tag_count(T const &tag);

/********************************************************
 uint8_t tags
 ********************************************************/
typedef uint8_t libdft_tag_uint8;

template <> struct tag_traits<unsigned char> {
  typedef unsigned char type;
  static const bool is_container = false;
  static const unsigned char cleared_val = 0;
  static const unsigned char set_val = 1;
};

template <>
unsigned char tag_combine(unsigned char const &lhs, unsigned char const &rhs);

template <> std::string tag_sprint(unsigned char const &tag);

template <> bool tag_count(unsigned char const &tag);

#endif /* LIBDFT_TAG_TRAITS_H */