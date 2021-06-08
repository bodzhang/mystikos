DRIVER=sgx_linux_x64_driver_1.41.bin

all: $(DRIVER)

##==============================================================================
##
## Rules to build and install the Intel SGX driver and libs
##
##==============================================================================

DRIVER_URL=https://download.01.org/intel-sgx/sgx-dcap/1.10.3/linux/distro/ubuntu18.04-server

$(DRIVER):
	wget $(DRIVER_URL)/$(DRIVER)

install: all
	sudo bash ./$(DRIVER)

clean:
	rm -f $(DRIVER)

distclean: clean
