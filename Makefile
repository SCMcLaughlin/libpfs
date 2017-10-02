
CFLAGS= 
COPT= -O2 -fomit-frame-pointer -std=c89 -fPIC
CWARN= -Wall -Wextra -Wredundant-decls
CWARNIGNORE= -Wno-unused-result -Wno-strict-aliasing
CDEF= 

ifdef debug
CFLAGS+= -O0 -g -Wno-format -fno-omit-frame-pointer
CDEF+= -DDEBUG
endif

_OBJECTS= pfs

OBJECTS= $(patsubst %,build/%.o,$(_OBJECTS))

##############################################################################
# Core Linker flags
##############################################################################
LFLAGS= -shared
LDYNAMIC= -lz
LSTATIC= 

##############################################################################
# Util
##############################################################################
Q= @
E= @echo -e
RM= rm -f 

##############################################################################
# Build rules
##############################################################################
.PHONY: default all clean

default all: libpfs.so

libpfs.so: $(OBJECTS)
	$(E) "Linking $@"
	$(Q)$(CC) -o $@ $^ $(LSTATIC) $(LDYNAMIC) $(LFLAGS)

build/%.o: %.c $($(CC) -M src/%.c)
	$(E) "\e[0;32mCC     $@\e(B\e[m"
	$(Q)$(CC) -c -o $@ $< $(CDEF) $(COPT) $(CWARN) $(CWARNIGNORE) $(CFLAGS)

clean:
	$(Q)$(RM) build/*.o
	$(Q)$(RM) libpfs.so
	$(E) "Cleaned build directory"

install:
	cp pfs.h /usr/include/
	cp libpfs.so /usr/lib/
	ldconfig -n /usr/lib
