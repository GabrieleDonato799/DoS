CC=gcc
ARGS=-Wall -pedantic -I. -g
OBJDIR=./obj
BINDIR=./bin

SRC=$(shell find . -name '*.c')  # recursively find all .c files in src
OBJS=$(patsubst ./%.c,$(OBJDIR)/%.o,$(SRC))
$(info Found these source files: ${SRC})
$(info Respective objects: ${OBJS})

$(OBJDIR)/%.o: %.c
	$(info $* $@ $<)
	@mkdir -p $(dir $@)
	$(CC) $(ARGS) -c $< -o $@ -lm

main: clean $(OBJS)
	@mkdir ./bin || exit 0
	$(CC) $(ARGS) -O3 $(OBJS) -o $(BINDIR)/main.app -lm

dbg: clean $(OBJS)
	@mkdir ./bin || exit 0
	$(CC) $(ARGS) -O0 $(OBJS) -o $(BINDIR)/main.app -lm

addrsan: clean $(OBJS)
	@mkdir ./bin || exit 0
	$(CC) $(ARGS) -O0 -fsanitize=address $(OBJS) -o $(BINDIR)/main.app -lm

run:
	./bin/main.app

clean:
	rm $(OBJDIR)/*.o $(OBJDIR)/*.s $(OBJDIR)/*.i $(BINDIR)/* || exit 0
	rm -r -d $(OBJDIR)/* $(BINDIR)/* || exit 0