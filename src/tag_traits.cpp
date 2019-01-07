#include <algorithm>
//#include <set>
//#include <bitset>
#include <string>
//#include <sstream>
#include "tag_traits.h"

/* *** Unsigned char based tags. ************************************/
template<>
unsigned char tag_combine(unsigned char const & lhs, unsigned char const & rhs) {
	return lhs | rhs;
}

template<>
void tag_combine_inplace(unsigned char & lhs, unsigned char const & rhs) {
	lhs |= rhs;
}

template<>
std::string tag_sprint(unsigned char const & tag) {
  // TODO: C++11
	//return std::bitset<(sizeof(tag) << 3)>(tag).to_string();
  return std::string();
}


/* *** set<uint32_t> based tags. ************************************/
/* define the set/cleared values */
/*
const std::set<uint32_t> tag_traits<std::set<uint32_t> >::cleared_val = std::set<uint32_t>();
//const std::set<uint32_t> tag_traits<std::set<uint32_t> >::set_val = std::set<uint32_t>();//{1}

template<>
std::set<uint32_t> tag_combine(std::set<uint32_t> const & lhs, std::set<uint32_t> const & rhs) {
	std::set<uint32_t> res;

	std::set_union(
			lhs.begin(), lhs.end(),
			rhs.begin(), rhs.end(),
			std::inserter(res, res.begin())
	);

	return res;
}

template<>
void tag_combine_inplace(std::set<uint32_t> & lhs, std::set<uint32_t> const & rhs) {
	lhs.insert(rhs.begin(), rhs.end());
}

template<>
std::string tag_sprint(std::set<uint32_t> const & tag) {
	std::set<uint32_t>::const_iterator t;
	std::stringstream ss;

	ss << "{";
	if (!tag.empty()) {
    //FIXME: not prev (c++11)
		std::set<uint32_t>::const_iterator last = std::prev(tag.end());
		for (t = tag.begin(); t != last; t++)
			ss << *t << ", ";
		ss << *(t++);
	}
	ss << "}";
	return ss.str();
}
*/

/* *** set<fdoff_t> based tags. ************************************/
/* 
   define the set/cleared values
   the set_val is kind of arbitrary here - represents offset 0 of stdin
 */
/*
const std::set<fdoff_t> tag_traits<std::set<fdoff_t> >::cleared_val = std::set<fdoff_t>();
//const std::set<fdoff_t> tag_traits<std::set<fdoff_t> >::set_val = std::set<fdoff_t>{fdoff_t{0, 0}};

template<>
std::set<fdoff_t> tag_combine(std::set<fdoff_t> const & lhs, std::set<fdoff_t> const & rhs) {
	std::set<fdoff_t> res;

	std::set_union(
		lhs.begin(), lhs.end(),
		rhs.begin(), rhs.end(),
		std::inserter(res, res.begin())
	);

	return res;
}

template<>
void tag_combine_inplace(std::set<fdoff_t> & lhs, std::set<fdoff_t> const & rhs) {
	lhs.insert(rhs.begin(), rhs.end());
}

template<>
std::string tag_sprint(std::set<fdoff_t> const & tag) {
  // FIXME: C++11
	std::set<fdoff_t>::const_iterator t;
	std::stringstream ss;
	ss << "{";
	if (!tag.empty()) {
		std::set<fdoff_t>::const_iterator last = std::prev(tag.end());
		for (t = tag.begin(); t != last; t++)
			ss << (*t).first << ":" << (*t).second << ", ";
		ss << (*t).first << ":" << (*t).second;
		t++;
	}
	ss << "}";
	return ss.str();
}
*/

/* *** bitset<> based tags. ****************************************/
/*
   define the set/cleared values
   the set_val is kind of arbitrary - represents all bits set
 */
/*
const std::bitset<TAG_BITSET_SIZE> tag_traits<std::bitset<TAG_BITSET_SIZE> >::cleared_val = std::bitset<TAG_BITSET_SIZE>();
//const std::bitset<TAG_BITSET_SIZE> tag_traits<std::bitset<TAG_BITSET_SIZE> >::set_val = std::bitset<TAG_BITSET_SIZE>().set();

template<>
std::bitset<TAG_BITSET_SIZE> tag_combine(std::bitset<TAG_BITSET_SIZE> const & lhs, std::bitset<TAG_BITSET_SIZE> const & rhs) {
	return lhs | rhs;
}

template<>
void tag_combine_inplace(std::bitset<TAG_BITSET_SIZE> & lhs, std::bitset<TAG_BITSET_SIZE> const & rhs) {
	lhs |= rhs;
}

template<>
std::string tag_sprint(std::bitset<TAG_BITSET_SIZE> const & tag) {
	//return tag.to_string();
  // FIXME: not c++11
  return std::string();
}
*/
/* *** range-list based tags. ****************************************/
#ifndef MIN
#  define MIN(_a,_b) ((_a) > (_b) ? (_b) : (_a))
#  define MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
#endif /* !MIN */

const std::vector<tag_seg> tag_traits<std::vector<tag_seg> >::cleared_val = std::vector<tag_seg>();
//const std::vector<tag_seg> tag_traits<std::vector<tag_seg> >::set_val = std::vector<tag_seg>{{0, 1}};

template<>
std::vector<tag_seg> tag_combine(std::vector<tag_seg> const & lhs, std::vector<tag_seg> const & rhs) {

  if (lhs.empty()) {
    return std::vector<tag_seg>(rhs);
  } else if (rhs.empty()) {
    return std::vector<tag_seg>(lhs);
  }

  std::vector<tag_seg> res;

  std::vector<tag_seg>::const_iterator s1 = lhs.begin();
  std::vector<tag_seg>::const_iterator s2 = rhs.begin();
  std::vector<tag_seg>::const_iterator e1 = lhs.end();
  std::vector<tag_seg>::const_iterator e2 = rhs.end();

  struct tag_seg last;

  if (s2 == e2 || (s1 != e1 && s1->begin < s2->begin)) {
    last = *(s1++);
  } else {
    last = *(s2++);
  }

  //auto cur = lhs.begin();
  std::vector<tag_seg>::const_iterator cur;

  while (s1 != e1 || s2 != e2) {

    if (s2 == e2 || (s1 != e1 && s1->begin < s2->begin)) {
      cur = s1++;
    } else {
      cur = s2++;
    }

    if (cur->begin <= last.end) {
      last.end = MAX(last.end, cur->end);
    } else {
      res.push_back(last);
      // I don;t want a large set; it will make the program slow and useless
      if (res.size() >= 4) return res;
      last = *cur;
    }

  }

  res.push_back(last);

	return res;

}

template<>
void tag_combine_inplace(std::vector<tag_seg> & lhs, std::vector<tag_seg> const & rhs) {

  std::vector<tag_seg> res = tag_combine(lhs, rhs);
  lhs.swap(res);

}

template<>
std::string tag_sprint(std::vector<tag_seg> const & tag) {
  /*
	std::stringstream ss;
  ss << "{";
  //for (auto p: tag) {
  for (std::vector<tag_seg>::const_iterator it = tag.begin() ; it != tag.end(); ++it) {

    ss << "(" << it->begin << ", " << it->end << "), ";
  }
	ss << "}";
	return ss.str();
  */
  return std::string();
}

/* *** tree tags. ****************************************/
// It's special that should initilize a global store for the set(tree)
// This step is done in tag_custom

TagNode* tag_traits<TagNode*>::cleared_val = NULL;
//TagNode* tag_traits<TagNode*>::set_val = NULL;


#include <iostream>
template<>
TagNode* tag_combine(TagNode* const &lhs,
                     TagNode* const &rhs) {
  return TagSet::combine(lhs, rhs);
}

template <>
void tag_combine_inplace(TagNode* &lhs,
                         TagNode* const &rhs) {
  lhs = TagSet::combine(lhs, rhs);
}


template <> std::string tag_sprint(TagNode* const &tag) {
  return TagSet::toString(tag);
}

/* vim: set noet ts=4 sts=4 : */
