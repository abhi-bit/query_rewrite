#include "view_file_reader.h"

static couchstore_error_t find_view_header_at_pos(view_group_info_t *info,
                                                cs_off_t pos)
{
    couchstore_error_t errcode = COUCHSTORE_SUCCESS;
    uint8_t buf;
    ssize_t readsize = info->file.ops->pread(&info->file.lastError,
                                            info->file.handle,
                                            &buf, 1, pos);
    error_unless(readsize == 1, COUCHSTORE_ERROR_READ);
    if (buf == 0) {
        return COUCHSTORE_ERROR_NO_HEADER;
    } else if (buf != 1) {
        return COUCHSTORE_ERROR_CORRUPT;
    }

    info->header_pos = pos;

    return COUCHSTORE_SUCCESS;

cleanup:
    return errcode;
}

static couchstore_error_t find_view_header(view_group_info_t *info,
                                        int64_t start_pos)
{
    couchstore_error_t last_header_errcode = COUCHSTORE_ERROR_NO_HEADER;
    int64_t pos = start_pos;
    pos -= pos % COUCH_BLOCK_SIZE;
    for (; pos >= 0; pos -= COUCH_BLOCK_SIZE) {
        couchstore_error_t errcode = find_view_header_at_pos(info, pos);
        switch(errcode) {
            case COUCHSTORE_SUCCESS:
                // Found it!
                return COUCHSTORE_SUCCESS;
            case COUCHSTORE_ERROR_NO_HEADER:
                // No header here, so keep going
                break;
            case COUCHSTORE_ERROR_ALLOC_FAIL:
                // Fatal error
                return errcode;
            default:
                // Invalid header; continue, but remember the last error
                last_header_errcode = errcode;
                break;
        }
    }
    return last_header_errcode;
}

int view_btree_cmp(const sized_buf *key1, const sized_buf *key2)
{
    return view_key_cmp(key1, key2, NULL);
}

int open_view_file(const char *filename, tree_file **file,
                   uint64_t *root_pointer)
{
    view_group_info_t *info;
    couchstore_error_t errcode;
    index_header_t *header = NULL;
    char *header_buf = NULL;
    int header_len;

    info = (view_group_info_t *)calloc(1, sizeof(view_group_info_t));
    if (info == NULL) {
        fprintf(stderr, "Unable to allocate memory\n");
        return -1;
    }
    info->type = VIEW_INDEX_TYPE_MAPREDUCE;

    errcode = open_view_group_file(filename, COUCHSTORE_OPEN_FLAG_RDONLY, &info->file);
    if (errcode != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Failed to open \"%s\": %s\n",
                filename, couchstore_strerror(errcode));
        return -1;
    } else {
        printf("Dumping \"%s\":\n", filename);
    }

    info->file.pos = info->file.ops->goto_eof(&info->file.lastError,
                                              info->file.handle);

    errcode = find_view_header(info, info->file.pos - 2);
    if (errcode != COUCHSTORE_SUCCESS) {
        fprintf(stderr, "Unable to find header position \"%s\": %s\n",
                filename, couchstore_strerror(errcode));
        return -1;
    }

    header_len = pread_header(&info->file, (cs_off_t)info->header_pos, &header_buf,
                            MAX_HEADER_SIZE);

    if (header_len < 0) {
        return -1;
    }

    errcode = decode_index_header(header_buf, (size_t) header_len, &header);
    free(header_buf);
    printf("Num views: %d\n", header->num_views);

    *root_pointer = header->view_states[0]->pointer;
    *file = &info->file;

    fflush(stderr);
    return 0;
}
