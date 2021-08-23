TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
TEST = pandas/tests/arrays/string_/test_string.py

OPTS = --nobrk --max-affinity-cpus=4

ifdef STRACE
OPTS += --strace
endif

all: rootfs cpiofs

appdir:
	$(APPBUILDER) Dockerfile

cpiofs: appdir
	$(MYST) mkcpio appdir cpiofs

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

run: rootfs
	$(MYST_EXEC) rootfs $(OPTS) --app-config-path config.json /usr/local/bin/python3 /app/app.py

run-cpio: cpiofs
	$(MYST_EXEC) cpiofs $(OPTS) --app-config-path config.json /usr/local/bin/python3 /app/app.py

one: rootfs
	$(MYST_EXEC) rootfs $(OPTS) --app-config-path config.json /usr/local/bin/python3 -m pytest /usr/local/lib/python3.9/site-packages/$(TEST)

cpio-one: rootfs
	$(MYST_EXEC) cpiofs $(OPTS) --app-config-path config.json /usr/local/bin/python3 -m pytest /usr/local/lib/python3.9/site-packages/$(TEST)

clean:
	rm -rf rootfs cpiofs appdir .pytest_cache
