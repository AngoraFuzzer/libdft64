//! Implements a data structure for sets.
// TODO: Mutex, support mutiple thread

#ifndef BDD_TAG_H
#define BDD_TAG_H

#include <algorithm>
#include <stdint.h>
#include <string>
#include <vector>

#define BDD_LB_WIDTH 24
#define BDD_LEN_LB 0xF0000000
#define BDD_LB_MASK 0x0FFFFFFF
#define BDD_HAS_LEN_LB(lb) (lb >= BDD_LEN_LB)
#define BDD_CLEAR_LEN_MASK(lb) (lb = lb & BDD_LB_MASK)

#ifndef BDD_TAG_SEG
#define BDD_TAG_SEG
typedef uint32_t lb_type;
typedef uint32_t tag_off;

struct tag_seg {
  bool sign;
  tag_off begin;
  tag_off end;
};

#endif

class TagNode {
public:
  lb_type left;
  lb_type right;
  lb_type parent;
  tag_seg seg; // offset of this segement
  TagNode(lb_type p, tag_off begin, tag_off end) {
    parent = p;
    left = 0;
    right = 0;
    seg.sign = false;
    seg.begin = begin;
    seg.end = end;
  };
  unsigned int get_seg_size() { return (seg.end - seg.begin); }
};

class BDDTag {
private:
  std::vector<TagNode> nodes;
  void dfs_clear(TagNode *cur_node);
  lb_type alloc_node(lb_type parent, tag_off begin, tag_off end);
  lb_type insert_n_zeros(lb_type cur_lb, size_t num, lb_type last_one_lb);
  lb_type insert_n_ones(lb_type cur_lb, size_t num, lb_type last_one_lb);

public:
  BDDTag();
  ~BDDTag();
  lb_type insert(tag_off pos);
  void set_sign(lb_type lb);
  bool get_sign(lb_type lb);
  void set_size(lb_type lb, size_t size);
  lb_type combine(lb_type lb1, lb_type lb2);

  const std::vector<tag_seg> find(lb_type lb);
  std::string to_string(lb_type lb);
};

#endif // LABEL_SET_H
