CFLAGS += -I. -pipe -Wall -Wextra -O2 -g
LDFLAGS += -lcrypto

RM := rm -f

raspi-smi-util: raspi-smi-util.o

.PHONY: clean
clean:
	$(RM) raspi-smi-util
	$(RM) raspi-smi-util.o
