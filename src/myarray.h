#ifndef MY_ARRAY_H
#define MY_ARRAY_H
//#include <algorithm>

template <typename _Tp, std::size_t _Nm> struct MyArray {
  // Support for zero-sized arrays mandatory.
  typedef _Tp value_type;
  typedef value_type &reference;
  typedef const value_type &const_reference;
  typedef std::size_t size_type;
  typedef value_type *iterator;
  typedef const value_type *const_iterator;

  value_type _M_instance[_Nm ? _Nm : 1];
  reference operator[](size_type __n) { return _M_instance[__n]; }
  const_reference operator[](size_type __n) const { return _M_instance[__n]; }
  size_type size() const { return _Nm; }

  // Iterators.
  iterator begin() { return iterator(&_M_instance[0]); }
  const_iterator begin() const { return const_iterator(&_M_instance[0]); }
  iterator end() { return iterator(&_M_instance[_Nm]); }
  const_iterator end() const { return const_iterator(&_M_instance[_Nm]); }
  void fill(const value_type &__u) { std::fill_n(begin(), size(), __u); }
};

#endif
