all: sizes constants

%: %.c
	clang -o $@ $<
# Debug pretty printer
print-%: ; @echo $*=$($*)

.PHONY: all
