.EXPORT_ALL_VARIABLES:

OSARCH=$(shell uname -s)
OSREV=$(shell uname -r)

VERSION := 1.22pre081119
DESTDIR ?=
CONFDIR:=/etc/asterisk
CONFDIR_REAL := $(DESTDIR)/etc/asterisk
PERMDIR:=/etc/asterisk
PERMDIR_REAL := $(DESTDIR)/etc/asterisk
DISTDIR:=/var/www/html/astmanproxy

LIBDIR := $(DESTDIR)/usr/lib/astmanproxy
CONFFILE := astmanproxy.conf
PERMFILE := astmanproxy.users

CC := gcc
INCLUDES :=
PREFIX:= /usr/local
BINDIR := $(DESTDIR)$(PREFIX)/sbin

# For compilation dependencies
MODS := astmanproxy config config_perms common proxyfunc log ssl md5
HANDLERS := xml standard csv http
SOBJS := $(HANDLERS:%=%.so)
LIBS := -lssl

# Add -g below for debug/GDB symbols
CFLAGS:=-Wall -O2 -D_REENTRANT -fPIC -Isrc/include -I/usr/include/openssl

ifeq (${OSARCH},Darwin)  
  LIBS+=-lresolv
  CFLAGS+=-D__Darwin_ -Iquotesrc/include
  BINDIR=/opt/sbin
  LIBDIR=/opt/lib/astmanproxy
  CONFDIR=/opt/etc/asterisk
  CONFDIR_REAL=/opt/etc/asterisk
  PERMDIR=/opt/etc/asterisk
  PERMDIR_REAL=/opt/etc/asterisk
  LOGDIR=/opt/log/asterisk
  CERTDIR := /opt/lib/asterisk/certs
  ifeq (${OSREV},7.9.0)
    OBJS+=poll.o dlfcn.o
  endif
  ASTLINK=-Wl,-force_flat_namespace,-dynamic
  SOLINK=-dynamic -bundle -undefined suppress -force_flat_namespace
  MKTEMP=/usr/bin/mktemp
else
  #These are used for all but Darwin
  CFLAGS+=-I-
  LIBS+=-ldl -pthread
  ASTLINK=-Wl,-E
  SOLINK=-shared -Xlinker -x
  LOGDIR=/var/log/asterisk   
  CERTDIR := /var/lib/asterisk/certs
  MKTEMP=/bin/mktemp
endif

MODDIR := $(LIBDIR)/modules
DEFINES:='-DPROXY_VERSION="$(VERSION)"' '-DCDIR="$(CONFDIR)"' '-DCFILE="$(CONFFILE)"'
DEFINES+='-DMDIR="$(MODDIR)"' '-DPDIR="$(PERMDIR)"' '-DPFILE="$(PERMFILE)"'

PROXYCERT := $(CERTDIR)/proxy-server.pem
PROXYSSLCONF := $(CONFDIR)/proxy-ssl.conf

CFLAGS += $(DEFINES)

OBJS += $(MODS:%=%.o)
CONF_TARGET:= $(CONFDIR_REAL)/$(CONFFILE)
PERM_TARGET:= $(PERMDIR_REAL)/$(PERMFILE)
VPATH = src


# For printing only
SRCS := $(MODS:%=src/%.c)
HDRS := src/include/astmanproxy.h

all: astmanproxy cert

astmanproxy: $(OBJS) $(SOBJS)
	$(CC) $(CFLAGS) -o $@ $(ASTLINK) $(OBJS) $(LIBS)

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(SOBJS): %.so: %.o
	$(CC) $(SOLINK) $< -o $@

SERIAL=`date "+%Y%m%d%H%M%S"`

cert:
	if [ ! -f $(PROXYCERT) ]; then      \
		umask 77 ; \
                PEM1=`$(MKTEMP) /tmp/openssl.XXXXXX` ; \
                PEM2=`$(MKTEMP) /tmp/openssl.XXXXXX` ; \
		if [ ! -f $(PROXYSSLCONF) ]; then \
			install ./configs/ssl.conf $(PROXYSSLCONF); \
		fi; \
		/usr/bin/openssl req $(UTF8) -newkey rsa:1024 -keyout $$PEM1 -nodes -x509 -days 365 -out $$PEM2 -set_serial $(SERIAL) -config $(PROXYSSLCONF) ; \
                mkdir -p $(CERTDIR); \
                cat $$PEM1 >  $(PROXYCERT) ; \
                echo ""    >> $(PROXYCERT) ; \
                cat $$PEM2 >> $(PROXYCERT) ; \
                rm $$PEM1 $$PEM2; \
	fi

certificate:
	createcert="1"; \
	if [ -f $(PROXYCERT) ]; then      \
                echo -n "The certificate already exists, Do you really want to create new one(yes/no)?"; \
                read answer;  \
                if [ "$$answer" = "yes" ]; then \
                        echo "I am creating a new certificate, Old one is copied as server.pem.old ";\
                        sudo cp /var/lib/asterisk/certs/server.pem /var/lib/asterisk/certs/server.pem.old; \
                elif [ "$$answer" = "no" ]; then \
                        echo "Certificate already exists, I am not creating a new certificate,";\
                        createcert="0"; \
                else \
                        echo "You need to enter either yes or no"; \
                        createcert="0"; \
                fi; \
        fi; \
        if [ "$$createcert" = "1" ]; then  \
		umask 77 ; \
                PEM1=`$(MKTEMP) /tmp/openssl.XXXXXX` ; \
                PEM2=`$(MKTEMP) /tmp/openssl.XXXXXX` ; \
		if [ ! -f $(PROXYSSLCONF) ]; then \
			install ./configs/ssl.conf $(PROXYSSLCONF); \
		fi; \
		/usr/bin/openssl req $(UTF8) -newkey rsa:1024 -keyout $$PEM1 -nodes -x509 -days 365 -out $$PEM2 -set_serial $(SERIAL) -config $(PROXYSSLCONF) ; \
                mkdir -p $(CERTDIR); \
                cat $$PEM1 >  $(PROXYCERT) ; \
                echo ""    >> $(PROXYCERT) ; \
                cat $$PEM2 >> $(PROXYCERT) ; \
                rm $$PEM1 $$PEM2; \
	fi


install: uninstall all
	install -d $(BINDIR)
	install astmanproxy $(BINDIR)
	install -d $(LIBDIR)
	install -d $(MODDIR)
	install $(SOBJS) $(MODDIR)
	install -d $(CONFDIR_REAL)
	if [ ! -f $(CONF_TARGET) ]; then \
		install ./configs/$(CONFFILE) $(CONF_TARGET); \
	fi
	if [ ! -f $(PERM_TARGET) ]; then \
		install ./configs/$(PERMFILE) $(PERM_TARGET); \
	fi
	@echo "Installation Complete!"

uninstall:
	rm -f $(BINDIR)/astmanproxy
	cd $(MODDIR); rm -f $(SOBJS)
	@echo "Successfully uninstalled!"

dist: clean
	rm -rf /tmp/astmanproxy-${VERSION}*; \
	cp -R . /tmp/astmanproxy-${VERSION}; \
	cd /tmp; tar czf /tmp/astmanproxy-${VERSION}-`date +%Y%m%d-%H%M`.tgz astmanproxy-${VERSION}; \
        /usr/bin/scp /tmp/astmanproxy-${VERSION}-*.tgz root@www.popvox.com:$(DISTDIR); \
	/usr/bin/ssh -lroot www.popvox.com "ln -sf $(DISTDIR)/astmanproxy-${VERSION}-*.tgz $(DISTDIR)/astmanproxy-latest.tgz"

clean:
	rm -f *.o *.so core *~ astmanproxy proxy-server.pem;

print:
	more Makefile $(HDRS) $(SRCS) | enscript -Ec -2r -j; exit 0
	@echo "Printing Complete!"

love:
	@echo "Here?  Now?"

# DO NOT DELETE
