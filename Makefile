CONTIKI_PROJECT = client server
all: $(CONTIKI_PROJECT)

TARGET=cooja

PROJECTDIRS += ids
PROJECT_SOURCEFILES += rpl_stats.c

LDLIBS += -lm

CONTIKI=contiki-ng
include $(CONTIKI)/Makefile.include
