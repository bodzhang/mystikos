TOP=$(abspath ../..)
include $(TOP)/defs.mak 

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS += --strace
endif

all: build

build: appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

tests:
# Run Pytest, keep the last 6 lines, remove ANSI color code, remove time code on line 6, compare with expected
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python /usr/local/bin/pytest --app-config-path config.json | tail -n 6 | \
		sed 's/\x1b\[[0-9;]*m//g' | sed '6 s/in [0-9]*\.[0-9]*s//' > result
	$(RUNTEST) diff result expected

tests_all:
# Run all tests
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python /usr/local/bin/pytest --app-config-path config.json

tests_single:
# Run single test for debugging
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python /usr/local/bin/pytest tests/test_instance_config.py::test_egg_installed_paths --app-config-path config_single.json

clean:
	rm -rf appdir rootfs result
