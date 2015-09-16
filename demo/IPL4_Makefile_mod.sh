#!/bin/sh

PLATFORM=
UR=`uname`
if [ "$UR" = "SunOS" ]; then
  UR2=`uname -r`
  if [ "$UR2" = "5.8" ]; then
    PLATFORM=SOLARIS8
  else
    PLATFORM=SOLARIS
  fi
else if [ "$UR" = "Linux" ]; then
  PLATFORM=LINUX
  else
    UR2=`uname -o 2>/dev/null`
    if [ "$UR2" = "Cygwin" ]; then
      PLATFORM=WIN32
    else
      echo 'Unknown platform'
      exit -1
    fi
  fi
fi

if [ `uname` = Linux ]; then
  editcmd='s/CPPFLAGS = -D$(PLATFORM) -I$(TTCN3_DIR)\/include/CPPFLAGS = -D$(PLATFORM) -DUSE_SCTP -DIP_AUTOCONFIG -I$(TTCN3_DIR)\/include/g
s/LINUX_LIBS =/LINUX_LIBS = -lpcap/g'
fi

if ( uname | grep CYGWIN ); then
  if [ `uname -o` == Cygwin ]; then
    editcmd='s/CPPFLAGS = -D$(PLATFORM) -I$(TTCN3_DIR)\/include/CPPFLAGS = -D$(PLATFORM) -DNO_IPV6 -I$(TTCN3_DIR)\/include/g'
  fi
fi

if [ `uname` = SunOS ]; then
  editcmd="s/$PLATFORM""_LIBS = -lsocket -lnsl/$PLATFORM""_LIBS = -lsocket -lnsl -lresolv/g"
fi

sed -e "$editcmd" <$1 >$2
