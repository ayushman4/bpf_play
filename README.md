**Compilation Instructions**
```
clang -g -O2 -target bpf  -D__TARGET_ARCH_x86_64 -I . -c restrict_imds_no_root.bpf.c -o restrict_imds_no_root.bpf.o
bpftool gen skeleton restrict_imds_no_root.bpf.o > restrict_imds_no_root.skel.h
clang -g -O2 -Wall -I . -c restrict_imds_no_root.c -o restrict_imds_no_root.o
clang -Wall -O2 -g restrict_imds_no_root.o libbpf/build/libbpf/libbpf.a -lelf -lz -o restrict_imds_no_root
```
**To run**
```
sudo ./restrict_imds_no_root
or 
sudo setcap cap_bpf,cap_perfmon+eip ./restrict_imds_no_root
./restrict_imds_no_root
```
