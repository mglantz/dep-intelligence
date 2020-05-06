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
		echo "$0: Unknown package manager"
		exit 1
	fi
fi

if [ "$RPM" == "yes" ]; then
	dnf install -y file binutils >/dev/null
elif [ "$APK" == "yes" ]; then
	apk add file binutils
fi

# Functions in the kernels syscall interface documented in latest syscalls manpage in F32
syscalls="_llseek _newselect _sysctl accept accept4 access acct add_key adjtimex alarm alloc_hugepages arc_gettls arc_settls arc_usr_cmpxchg arch_prctl atomic_barrier atomic_cmpxchg_32 bdflush since bfin_spinlock bind bpf brk breakpoint __ARM_NR cacheflush capget capset chdir chmod chown version chown32 chroot clock_adjtime clock_getres clock_gettime clock_nanosleep clock_settime clone2 clone clone3 close cmpxchg_badaddr connect copy_file_range creat create_module delete_module dma_memcpy dup dup2 dup3 epoll_create epoll_create1 epoll_ctl epoll_pwait epoll_wait eventfd eventfd2 execv compatibility execve execveat exit exit_group faccessat fadvise64 fadvise64_64 fallocate fanotify_init fanotify_mark fchdir fchmod fchmodat fchown fchown32 fchownat fcntl fcntl64 fdatasync fgetxattr finit_module flistxattr flock fork free_hugepages fremovexattr fsconfig fsetxattr fsmount fsopen fspick fstat fstat64 fstatat64 fstatfs fstatfs64 fsync ftruncate ftruncate64 futex futimesat get_kernel_syms get_mempolicy get_robust_list get_thread_area get_tls __ARM_NR getcpu getcwd getdents getdents64 getdomainname getdtablesize available osf_getdtablesize getegid getegid32 geteuid geteuid32 getgid getgid32 getgroups getgroups32 gethostname getitimer getpeername getpagesize getpgid getpgrp getpid getppid getpriority getrandom getresgid getresgid32 getresuid getresuid32 getrlimit getrusage getsid getsockname getsockopt gettid gettimeofday getuid getuid32 getunwind getxattr getxgid getxpid getxuid init_module inotify_add_watch inotify_init inotify_init1 inotify_rm_watch io_cancel io_destroy io_getevents io_pgetevents io_setup io_submit io_uring_enter io_uring_register io_uring_setup ioctl ioperm iopl ioprio_get ioprio_set ipc kcmp kern_features kexec_file_load kexec_load keyctl kill lchown version lchown32 lgetxattr link linkat listen listxattr llistxattr lookup_dcookie lremovexattr lseek lsetxattr lstat lstat64 madvise mbind memory_ordering metag_get_tls metag_set_fpu_flags metag_set_tls metag_setglobalbit membarrier memfd_create migrate_pages mincore mkdir mkdirat mknod mknodat mlock mlock2 mlockall mmap mmap2 modify_ldt mount move_mount move_pages mprotect mq_getsetattr mq_notify mq_open mq_timedreceive mq_timedsend mq_unlink mremap msgctl msgget msgrcv msgsnd msync munlock munlockall munmap name_to_handle_at nanosleep newfstatat nfsservctl nice old_adjtimex old_getrlimit oldfstat oldlstat oldolduname oldstat oldumount syscall olduname open open_by_handle_at open_tree openat openat2 or1k_atomic pause pciconfig_iobase pciconfig_read pciconfig_write perf_event_open personality perfctr perfmonctl pidfd_getfd pidfd_send_signal pidfd_open pipe pipe2 pivot_root pkey_alloc pkey_free pkey_mprotect poll ppoll prctl pread pread64 renamed preadv preadv2 prlimit64 process_vm_readv process_vm_writev pselect6 ptrace pwrite pwrite64 renamed pwritev pwritev2 query_module quotactl read readahead readdir readlink readlinkat readv reboot recv recvfrom recvmsg recvmmsg remap_file_pages removexattr rename renameat renameat2 request_key restart_syscall riscv_flush_icache rmdir rseq rt_sigaction rt_sigpending rt_sigprocmask rt_sigqueueinfo rt_sigreturn rt_sigsuspend rt_sigtimedwait rt_tgsigqueueinfo rtas s390_runtime_instr s390_pci_mmio_read s390_pci_mmio_write s390_sthyi s390_guarded_storage sched_get_affinity sched_get_priority_max sched_get_priority_min sched_getaffinity sched_getattr sched_getparam sched_getscheduler sched_rr_get_interval sched_set_affinity sched_setaffinity sched_setattr sched_setparam sched_setscheduler sched_yield seccomp select semctl semget semop semtimedop send sendfile sendfile64 sendmmsg sendmsg sendto set_mempolicy set_robust_list set_thread_area set_tid_address set_tls setdomainname setfsgid setfsgid32 setfsuid setfsuid32 setgid setgid32 setgroups setgroups32 sethae sethostname setitimer setns setpgid setpgrp setpgid setpriority setregid setregid32 setresgid setresgid32 setresuid setresuid32 setreuid setreuid32 setrlimit setsid setsockopt settimeofday setuid setuid32 setup setxattr sgetmask shmat shmctl shmdt shmget shutdown sigaction sigaltstack signal signalfd signalfd4 sigpending sigprocmask sigreturn sigsuspend socket socketcall socketpair spill splice spu_create spu_run sram_alloc sram_free ssetmask stat stat64 statfs statfs64 statx stime subpage_prot swapcontext switch_endian swapcontext swapoff swapon symlink symlinkat sync sync_file_range sync_file_range2 syncfs sys_debug_setcontext syscall sysfs sysinfo syslog sysmips tee tgkill time timer_create timer_delete timer_getoverrun timer_gettime timer_settime timerfd_create timerfd_gettime timerfd_settime times tkill truncate truncate64 ugetrlimit umask umount umount2 uname unlink unlinkat unshare uselib ustat userfaultfd usr26 usr32 utime utimensat utimes utrap_install vfork vhangup vm86old vmsplice wait4 waitid waitpid write writev xtensa"

if echo $2|grep -i new >/dev/null
then
	rm -f $1*
	# Generate a raw mapping of RPMs or ELF binaries mapped to syscalls, library and kernel alike
	# Filter out functions not present in the kernel syscall interface, or we'll get 4.5m things.
	if [ "$RPM" == "yes" ]
	then
		for therpm in $(rpm -qa|grep -v kernel)
		do
			for file in $(rpm -ql $therpm)
			do	
				if file $file|grep "ELF 64" >/dev/null
				then
					for syscall in $(nm $file 2>/dev/null|grep U|awk '{ print $2 }')
					do
						if echo $syscalls|grep "$syscall" >/dev/null
						then
							echo "$therpm $syscall"
						fi	
					done
					for syscall in $(nm -D $file 2>/dev/null|grep U|awk '{ print $2 }')
					do
						if echo $syscalls|grep "$syscall" >/dev/null
						then
							echo "$therpm $syscall";
						fi
					done
				fi
			done
		done|sort -u|tr '[:upper:]' '[:lower:]'|grep -v "@"|grep -vw "[a-z]"|grep -v " _" >$1.all.raw
	elif [ "$APK" == "yes" ]
	then
		for file in $(find . -type f|grep -v kernel)
		do
				if file $file|grep "ELF 64" >/dev/null
				then
					for syscall in $(nm $file 2>/dev/null|grep U|awk '{ print $2 }')
					do
						if echo $syscalls|grep "$syscall" >/dev/null
						then
							echo "$file $syscall"
						fi
					done
					for syscall in $(nm -D $file 2>/dev/null|grep U|awk '{ print $2 }')
					do
						if echo $syscalls|grep "$syscall" >/dev/null
						then
							echo "$file $syscall";
						fi
					done
				fi
		done|sort -u|tr '[:upper:]' '[:lower:]'|grep -v "@"|grep -vw "[a-z]"|grep -v " _" >$1.all.raw
	fi
fi

# Exclude libraries
grep -v lib $1.all.raw >$1.bin.raw

# Include libraries
grep lib $1.all.raw >$1.lib.raw

# Create start of json files
for item in bin lib all
do
	echo "{\"graph\": [], \"links\":[" >$1.$item.csv
done

# Source target relationships
for item in bin lib all
do
	for therpm in $(awk '{ print $1 }' $1.${item}.raw|sort -u)
	do
		for syscall in $(grep $therpm $1.${item}.raw|awk '{ print $2 }')
		do
			echo "{\"source\": \"$therpm\", \"target\": \"$syscall\", \"value\": 1}," >>$1.$item.csv
		done
	done
done

# Add kernel syscalls as sources, all pointing to hardware. And hardware pointing to itself.
# FIXME: add different hardware resources, yes, I mean read all syscall manpages.
for item in bin lib all
do
	for syscall in $(awk '{ print $2 }' $1.${item}.raw|sort -u)
	do
		echo "{\"source\": \"$syscall\", \"target\": \"hardware\", \"value\": 1}," >>$1.$item.csv
	done
	echo "{\"source\": \"hardware\", \"target\": \"hardware\", \"value\": 1} ], \"nodes\" :[" >>$1.$item.csv
done

# Add IDs for RPMs, kernel syscalls and hardware at the end
for item in bin lib all
do
	for therpm in $(awk '{ print $1 }' $1.${item}.raw|sort -u)
	do
		echo "{\"id\": \"$therpm\", \"group\": \"app\", \"score\":0}," >>$1.$item.csv
	done

	for syscall in $(awk '{ print $2 }' $1.${item}.raw|sort -u)
	do
		echo "{\"id\": \"$syscall\", \"group\": \"kernel\", \"score\":0}," >>$1.$item.csv
	done
	echo "{\"id\": \"hardware\", \"group\": \"hardware\", \"score\":0}]}" >>$1.$item.csv
done
