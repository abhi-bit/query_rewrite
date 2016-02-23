//C libraries
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>

// Couchstore libraries
#include "bitfield.h"
#include "config.h"
#include "couch_btree.h"
#include "internal.h"
#include <libcouchstore/couch_db.h>
#include "node_types.h"
#include <snappy-c.h>
#include "util.h"
#include "views/util.h"
#include "views/index_header.h"
#include "views/view_group.h"

#define MAX_HEADER_SIZE (64 * 1024)

static couchstore_error_t find_view_header(view_group_info_t *info,
                                        int64_t start_pos);
//TODO: really need to return static int?
int view_btree_cmp(const sized_buf *key1, const sized_buf *key2);
int open_view_file(const char *filename, tree_file **file,
                   uint64_t *root_pointer);
