
CC_OPT=-w -Wall -Wextra -Werror -Wno-format-extra-args -Wformat=2 -fstack-protector-all -fPIE -pie -D_FORTIFY_SOURCE=2

all: esuexec

debug: esuexec.c
	gcc -DDEBUGP $(CC_OPT) $< -o ${<:.c=}

%: %.c
	gcc $(CC_OPT) $< -o ${<:.c=}

clean:
	rm -f esuexec
