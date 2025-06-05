#!/bin/sh
qemu-system-x86_64 \
    -m 256M \
    -kernel ./bzImage \
    -initrd ./root_updated.cpio.gz \
    -append "root=/dev/ram rw console=ttyS0 loglevel=3 panic=1 kaslr quiet" \
    -no-reboot \
    -net nic,model=virtio \
    -cpu kvm64,+smep,+smap \
    -monitor /dev/null \
    -nographic \
    -gdb tcp::12345
