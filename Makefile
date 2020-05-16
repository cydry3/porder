CFLAGS=-Wall 
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

task: clean porder

porder: $(OBJS)
	$(CC) -o porder $(OBJS) $(LDFLAGS)

$(OBJS): porder.h

.PHONY: test clean
test: porder
	./test.sh

clean:
	rm -f porder *.o *~ tmp*


