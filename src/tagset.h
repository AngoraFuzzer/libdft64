//! Implements a data structure for sets.
// TODO: Mutex, support mutiple thread

#ifndef TAG_SET_H
#define TAG_SET_H

#include <algorithm>
#include <stdint.h>
#include <string>
#include <vector>

#ifndef TAG_SEG
#define TAG_SEG
typedef uint16_t tag_off;

struct tag_seg {
  uint32_t sign;
  tag_off begin;
  tag_off end;
};
#endif

class TagNode {
public:
  TagNode *left;
  TagNode *right;
  TagNode *parent;
  // A range conclude multiple segements.
  // E.g. [{seg0.begin, seg0.end}, {seg1.begin, seg1.end} ... ]
  TagNode *prev_seg_node; // node at the end of prev segement.
  tag_seg seg;            // offset of this segement
  TagNode(TagNode *p) {
    parent = p;
    left = NULL;
    right = NULL;
    prev_seg_node = NULL;
    seg.begin = 0;
    seg.end = 0;
  };
};

#define MEM_BLOCK_SIZE 0xffff

class TagSet {
private:
  TagNode *root; // Root of the tree
  /*
             i-th
    | .. | 0 | size | 0 | 0 | .. |
   */
  tag_off mem_block[MEM_BLOCK_SIZE];

  void dfs_clear(TagNode *cur_node);
  // TagNode* _insert(const std::vector<bool> &v);

public:
  TagSet();
  ~TagSet();
  // TagNode* untainted();
  TagNode *insert(tag_off pos);
  void _insert_block(tag_off off, uint32_t size);
  void mem_read(TagNode *const *tag, uint32_t size);
  void frac_tagvec(std::vector<tag_seg> &tag_vec);
  static TagNode *combine(TagNode *node1, TagNode *node2);
  static const std::vector<tag_seg> find(TagNode *node);
  static std::string toString(TagNode *const node);
  static void show(TagNode *node);
};

#endif // LABEL_SET_H
