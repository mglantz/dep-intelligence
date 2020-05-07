#!/bin/bash

# Prereqs
if ! whoami|grep root >/dev/null
then
	echo "$0: You need to be root to run this."
	exit 1
fi

which rpm >/dev/null
if [ "$?" -eq 0 ]; then
	RPM="yes"
else
	which apk
	if [ "$?" -eq 0 ]; then
		APK="yes"
	else
		which apt-get
		if [ "$?" -eq 0 ]; then
			APTGET="yes"
		else
			echo "$0: Unknown package manager"
			exit 1
		fi
	fi
fi

if [ "$RPM" == "yes" ]; then
	dnf install -y file binutils >/dev/null
elif [ "$APK" == "yes" ]; then
	apk add file binutils
elif [ "$APTGET" == "yes" ]; then
	apt-get update
	apt-get -y install binutils file wget
fi

if echo $2|grep -i new >/dev/null
then
	rm -f $1*
	for file in $(find . -type f)
	do
		if file $file|grep "ELF 64" >/dev/null
		then
			filemd5=$(md5sum $file|awk '{ print $1 }')
			for syscall in $(nm --with-symbol-versions $file 2>/dev/null|egrep -iw '(u|w)'|awk '{ print $2 }')
			do
				echo "$filemd5 $syscall"
			done
			for syscall in $(nm --with-symbol-versions $file 2>/dev/null|egrep -iw '(t|d)' |awk '{ print $3 }')
			do
				echo "$filemd5 $syscall"
			done
		fi
	done|tr '[:upper:]' '[:lower:]'|sort -u>$1.all.deps
fi
