TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
TEST = pandas/tests/extension/test_boolean.py

OPTS = --nobrk --max-affinity-cpus=1

ifdef STRACE
OPTS += --strace
endif

all: rootfs

appdir:
	$(APPBUILDER) Dockerfile
	rm appdir/usr/local/lib/python3.9/site-packages/pandas/tests/computation/test_eval.py

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

run: rootfs
	$(MYST_EXEC) rootfs $(OPTS) --app-config-path config.json /usr/local/bin/python3 /app/app.py

one: rootfs
	$(MYST_EXEC) rootfs $(OPTS) --app-config-path config.json /usr/local/bin/python3 -m pytest /usr/local/lib/python3.9/site-packages/$(TEST)

clean:
	rm -rf rootfs appdir .pytest_cache
