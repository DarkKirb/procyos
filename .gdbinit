target remote :1234
add-symbol-file ~/.cache/rust/x86_64-kernel-procyos/debug/kernel
break _start
continue