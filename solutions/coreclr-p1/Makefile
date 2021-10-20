TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=corerun
TEST_CASE= \
baseservices/threading/paramthreadstart/ThreadStartUShort/ThreadStartUShort.dll max
PACKAGE_PATH  = myst/bin/corerun
ifdef STRACE
OPTS += --strace
endif
OPTS += --app-config-path=config_20g.json

all: ext2fs build-package

# docker build time ~1hr. Using prebuilt image.
# Other docker images:
# pr1(~10k tests) tests in debug
#$(APPBUILDER) vtikoo/coreclr-tests:release
# runtime with debug symbols -
#$(APPBUILDER) vtikoo/coreclr-tests:debug3
appdir:
	# pr0(~2.7k tests) tests in release
	$(APPBUILDER) -i vtikoo/coreclr-tests:release

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs

build-package: package.pem
	$(MYST) fssig --roothash ext2fs > roothash
	$(MYST) package-sgx --roothash=roothash package.pem config_256m.json

custom-test-runs:
	./run-single-test.sh $(MYST_EXEC) config_256m.json 300 ext2 \
	JIT/Regression/CLR-x86-JIT/V1-M09/b16102/b16102/b16102.dll 0
	./run-single-test.sh $(MYST_EXEC) config_256m.json 300 ext2 \
	JIT/jit64/regress/vsw/102754/test1/test1.dll 0
	# Change CWD using mystikos config for the following tests to run successfully
	sed -i '19 i \ \ \ \ "CurrentWorkingDirectory":"/coreclr-tests-all/Interop/COM/Reflection/Reflection",' config_1g.json
	./run-single-test.sh $(MYST_EXEC) config_1g.json 300 ext2 \
	Interop/COM/Reflection/Reflection/Reflection.dll
	sed -i '19d' config_1g.json
	sed -i '19 i \ \ \ \ "CurrentWorkingDirectory":"/coreclr-tests-all/JIT/Regression/JitBlue/DevDiv_461649/DevDiv_461649",' config_1g.json
	./run-single-test.sh $(MYST_EXEC) config_1g.json 300 ext2 \
	JIT/Regression/JitBlue/DevDiv_461649/DevDiv_461649/DevDiv_461649.dll
	sed -i '19d' config_1g.json
	sed -i '19 i \ \ \ \ "CurrentWorkingDirectory":"/coreclr-tests-all/Interop/DllImportAttribute/DllImportPath/DllImportPathTest/",' config_1g.json
	./run-single-test.sh $(MYST_EXEC) config_1g.json 300 ext2 \
	Interop/DllImportAttribute/DllImportPath/DllImportPathTest/DllImportPathTest.dll
	sed -i '19d' config_1g.json

run:
	./test-runner.sh $(PACKAGE_PATH) null null 120 package pr1-256m 100
	./test-runner.sh $(MYST_EXEC) config_1g.json 300 ext2 pr1-1g-passed 100
	./test-runner.sh $(MYST_EXEC) config_3g.json 120 ext2 pr1-3g-passed 100
	./test-runner.sh $(MYST_EXEC) config_3g.json 720 ext2  pr1-3g-720 100
	./test-runner.sh $(MYST_EXEC) config_8g.json 300 ext2 pr1-8g-passed 100
	$(MAKE) custom-test-runs
	# Model number 106 or 108 indicates IceLake machines
	if cat /proc/cpuinfo | grep -m 1 "model.*:" | grep '106\|108' > /dev/null; then \
	./test-runner.sh $(MYST_EXEC) config_1g.json 300 ext2 pr1-icelake-1g-passed 100; \
	./test-runner.sh $(MYST_EXEC) config_8g.json 900 ext2 pr1-icelake-8g-passed; \
	fi
	./stat.h
	 
package.pem:
	openssl genrsa -out package.pem -3 3072

clean:
	sudo rm -fr appdir ext2fs rootfs roothash myst /tmp/myst* PASSED FAILED-*

tests:
	@ $(MAKE) -s clean
	@ $(MAKE) -s all
	@ $(MAKE) -s run

##################################
#			dev targets			 #
##################################

run-ext2:
	$(MYST_EXEC) ext2fs $(OPTS) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	./coreclr-tests-all/$(TEST_CASE)

run-ext2-gdb:
	$(MYST_GDB) --args $(MYST_EXEC) ext2fs $(OPTS) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/$(TEST_CASE)

ct:
	sudo rm -fr /tmp/myst* PASSED FAILED-*

