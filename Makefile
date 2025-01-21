CONTIKI_PROJECT = client server
all: $(CONTIKI_PROJECT)

TARGET=cooja

CONTIKI=contiki-ng
include $(CONTIKI)/Makefile.include
