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
	# excluding sys, proc and tmp
	for file in $(find $(find / -maxdepth 1 -type d|grep -v proc|grep -v sys|grep -v tmp|grep -vw "/"|grep -v home|grep -v dev|grep -v "lost+found") -type f)
	do
		filemd5=$(md5sum $file|awk '{ print $1 }')
		if file $file|grep "ELF 64" >/dev/null
		then
			for syscall in $(nm --with-symbol-versions $file 2>/dev/null|grep U|awk '{ print $2 }')
			do
				echo "$filemd5 $syscall"
			done
			for syscall in $(nm -D --with-symbol-versions $file 2>/dev/null|grep U|awk '{ print $2 }')
			do
				echo "$filemd5 $syscall"
			done
		else
			echo "$filemd5 $file"
		fi	
	done|tr '[:upper:]' '[:lower:]'|sort -u>$1.all.deps
fi
