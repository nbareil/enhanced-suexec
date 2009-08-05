
CC_OPT=-Wall -Wextra -Wno-format-extra-args -Wformat=2 -w -pedantic -fstack-protector-all -fPIE -pie -D_FORTIFY_SOURCE=2

all: esuexec

%: %.c
	gcc $(CC_OPT) $< -o ${<:.c=}

clean:
	rm esuexec
