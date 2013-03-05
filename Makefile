TESTS := test-b64 ub64 eb64

TEST_DIR := test
TESTS := $(addprefix $(TEST_DIR)/,$(TESTS))

override CFLAGS := -I. $(CFLAGS)

.PHONY: all tests

all: tests

tests: $(TESTS)

$(TESTS): b64.o $(addsuffix .o, $(TESTS))
	$(CC) -o $@ b64.o $@.o

clean:
	rm -f *.o $(TEST_DIR)/*.o $(TESTS)
