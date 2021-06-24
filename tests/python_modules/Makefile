TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS += --strace
endif

all: ext2fs

appdir:
	$(APPBUILDER) Dockerfile

ext2fs: appdir
	sudo $(MYST) mkext2 appdir ext2fs
	sudo chown $(USER).$(USER) ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

tests:
	$(RUNTEST) $(MYST_EXEC) --roothash=roothash ext2fs \
	/miniconda/bin/python3 /app/app.py \
	--app-config-path config.json

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) --roothash=roothash ext2fs \
	/miniconda/bin/python3 /app/app.py \
	--app-config-path config.json

clean:
	rm -fr appdir ext2fs roothash

