#include <iostream>
#include <cstring>
#include <map>
#include <vector>

#include <curl/curl.h>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

typedef struct {
    char *data;
    size_t size;
} mem_data;

std::map<std::string, std::vector<int> > get_partiton_map();
