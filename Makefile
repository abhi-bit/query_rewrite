CC=clang++
COUCHBASE_INSTALL_DIR=/home/vagrant/master
CXXFLAGS=-Wl,-rpath=$(COUCHBASE_INSTALL_DIR)/install/lib/
FILES=cquery.cc vbmap.cc view_file_reader.cc
OUT_FILE=query_server
INCLUDE_DIRS=-I$(COUCHBASE_INSTALL_DIR)/couchstore/include \
			 -I$(COUCHBASE_INSTALL_DIR)/couchstore/src \
			 -I$(COUCHBASE_INSTALL_DIR)/build/couchstore \
			 -I$(COUCHBASE_INSTALL_DIR)/platform/include \
			 -I$(COUCHBASE_INSTALL_DIR)/build/platform/include \
			 -I/usr/local/include/evhtp
LINK_MODS=-luv -levent -levhtp -lhttp_parser -lcurl -lcouchstore
LINK_LIBS=-L $(COUCHBASE_INSTALL_DIR)/install/lib \
		  -L /usr/local/lib

all:
	$(CC) $(CXXFLAGS) $(FILES) $(INCLUDE_DIRS) $(LINK_MODS) $(LINK_LIBS) \
		-o $(OUT_FILE)

run:
	./$(OUT_FILE)

clean:
	rm -rf $(OUT_FILE)
