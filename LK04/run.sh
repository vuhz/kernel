#!/bin/sh
qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -cpu kvm64,+smap,+smep \
    -monitor /dev/null \
    -initrd root_updated.cpio.gz \
    -net nic,model=virtio \
    -net user \
    -gdb tcp::12345
