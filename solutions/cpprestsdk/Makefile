.PHONY: all package ext2fs gdb

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER    = $(TOP)/scripts/appbuilder
APPDIR        = appdir
APP_NAME      = test_runner

ifdef STRACE
OPTS = --strace
endif

all: package

package: ext2fs private.pem
	$(MYST) package-sgx --roothash=roothash private.pem config.json

run: 
	myst/bin/$(APP_NAME) $(OPTS) --rootfs=ext2fs

$(APPDIR):
	$(APPBUILDER) -v -d Dockerfile

ext2fs: $(APPDIR)
	$(MYST) mkext2 $(APPDIR) ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

# There are 6 test suite come with the CPPRESTSDK, replace the <suite>.so filename to related test suite
# libhttpclient_test.so
# libhttplistener_test.so
# libjson_test.so
# libpplx_test.so
# libstreams_test.so
# liburi_test.so
run-one:
	$(MYST_EXEC) ext2fs /app/casablanca/build.release/Release/Binaries/test_runner libhttplistener_test.so --app-config-path debug-config.json $(OPTS)

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) ext2fs /app/casablanca/build.release/Release/Binaries/test_runner libhttplistener_test.so --app-config-path debug-config.json $(OPTS)

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	rm -rf rootfs ext2fs roothash $(APPDIR) myst private.pem 
