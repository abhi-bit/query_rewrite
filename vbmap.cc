#include "vbmap.h"

static size_t write_memory_callback(void *contents, size_t size,
                                    size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    mem_data *mem = (mem_data *) userp;

    mem->data = (char *) realloc(mem->data, mem->size + realsize + 1);
    if (mem->data == NULL) {
        fprintf(stderr, "Not enough memory available\n");
        return 0;
    }

    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

std::map<std::string, std::vector<int> > get_partiton_map()
{
    CURL            *curl_handle;
    CURLcode        res;
    mem_data        chunk;

    chunk.data = (char *) malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL,
                       "http://apple:8091/pools/default/buckets/default");
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_memory_callback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    res = curl_easy_perform(curl_handle);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() had failures %s\n",
                curl_easy_strerror(res));
    }

    // TODO: add assert here
    std::string data(chunk.data);

    rapidjson::Document doc;
    if (doc.Parse(data.c_str()).HasParseError()) {
        std::cout << "Facing issue with parsing" << std::endl;
        exit(0);
    }
    std::cout << "bucket map parsing succeeded\n" << std::endl;

    std::map<std::string, std::vector<int> > partitionStates;
    assert(doc.IsObject());
    {
        rapidjson::Value& vbmap = doc["vBucketServerMap"]["vBucketMap"];
        rapidjson::Value& serverList = doc["vBucketServerMap"]["serverList"];
        assert(vbmap.IsArray());
        assert(serverList.IsArray());

        for (rapidjson::SizeType i = 0; i < vbmap.Size(); i++) {
            partitionStates[serverList[vbmap[i][0].GetInt()].GetString()].push_back(i);
        }

        for (std::map<std::string, std::vector<int> >::iterator it = partitionStates.begin();
                it != partitionStates.end(); ++it) {
            std::cout << it->first << " => ";
            for (int j = 0; j < it->second.size(); j++) {
                std::cout << it->second[j] << " ";
            }
            std::cout << std::endl;
        }
    }
    return partitionStates;
}
