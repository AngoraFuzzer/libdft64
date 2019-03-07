#include "tagset.h"
#include "debug.h"
#include <assert.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stack>

TagSet::TagSet() {
  // The root node has no parent.
  root = new TagNode(NULL);
  memset(mem_block, 1, MEM_BLOCK_SIZE * sizeof(tag_off));
};

TagSet::~TagSet() { dfs_clear(root); };

void TagSet::dfs_clear(TagNode *cur_node) {
  if (!cur_node)
    return;
  dfs_clear(cur_node->left);
  dfs_clear(cur_node->right);
  delete cur_node;
};

TagNode *TagSet::insert(tag_off pos) {
  // return NULL;
  TagNode *cur_node = root;
  for (int i = 0; i < pos; i++) {
    if (!cur_node->left)
      cur_node->left = new TagNode(cur_node);
    cur_node = cur_node->left;
  }

  if (!cur_node->right) {
    cur_node->right = new TagNode(cur_node);
    cur_node = cur_node->right;
    cur_node->seg.begin = pos;
    cur_node->seg.end = static_cast<tag_off>(pos + 1);
  } else {
    cur_node = cur_node->right;
  }

  return cur_node;
};

const std::vector<tag_seg> TagSet::find(TagNode *node) {

  std::vector<tag_seg> v;
  TagNode *cur_node = node;

  while (cur_node) { //&& cur_node->seg.size != 0
    v.push_back(cur_node->seg);
    cur_node = cur_node->prev_seg_node;
  }

  std::reverse(v.begin(), v.end());

  return v;
};

void TagSet::show(TagNode *node) { std::cout << toString(node) << std::endl; }

std::string TagSet::toString(TagNode *const node) {
  std::string ss = "";
  ss += "{";
  std::vector<tag_seg> tags = find(node);
  char buf[100];
  for (std::vector<tag_seg>::iterator it = tags.begin(); it != tags.end();
       ++it) {
    sprintf(buf, "(%d, %d) ", it->begin, it->end);
    std::string s(buf);
    ss += s;
  }
  ss += "}";
  return ss;
}

TagNode *TagSet::combine(TagNode *node1, TagNode *node2) {
  if (!node1) {
    return node2;
  } else if (!node2 || node1 == node2) {
    return node1;
  }

  // get all the segments
  std::stack<tag_seg> seg_st;
  while (node1 && node2) {
    if (node1->seg.begin <= node2->seg.begin) {
      seg_st.push(node2->seg);
      node2 = node2->prev_seg_node;
    } else { // node2 <= node1
      seg_st.push(node1->seg);
      node1 = node1->prev_seg_node;
    }
  }

  TagNode *cur_node = NULL;
  if (node1) {
    cur_node = node1;
  } else {
    cur_node = node2;
  }
  // assert(cur_node);
  int i;

  while (!seg_st.empty()) {
    tag_seg cur_seg = cur_node->seg;
    TagNode *node_tmp = cur_node;
    tag_seg next_seg = seg_st.top();
    seg_st.pop();

    // has overlapping or next to each
    if (cur_seg.end >= next_seg.begin) {
      // tag_off total_size = next_seg.end - cur_seg.begin;
      tag_off remain = next_seg.end - cur_seg.end;
      if (remain > 0) {
        for (i = 0; i < remain; i++) {
          if (!cur_node->right)
            cur_node->right = new TagNode(cur_node);
          cur_node = cur_node->right;
        }
        cur_node->seg.begin = cur_seg.begin;
        cur_node->seg.end = next_seg.end;
        cur_node->prev_seg_node = node_tmp->prev_seg_node;
      }
    } else {
      // has gap
      tag_off gap = next_seg.begin - cur_seg.end;
      for (i = 0; i < gap; i++) {
        if (!cur_node->left)
          cur_node->left = new TagNode(cur_node);
        cur_node = cur_node->left;
      }
      for (i = next_seg.begin; i < next_seg.end; i++) {
        if (!cur_node->right)
          cur_node->right = new TagNode(cur_node);
        cur_node = cur_node->right;
      }
      cur_node->seg = next_seg;
      cur_node->prev_seg_node = node_tmp;
    }
  }
  assert(cur_node->seg.begin != cur_node->seg.end);
  return cur_node;
};
