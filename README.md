# Clone Android Header Info

Tool to copy metadata from one android boot image to another.
Use during custom kernels installation to clone os\_patch\_date and avoid OS rollback protection.
Supported android image formats: V0, V1, V2. V3 is not supported. Documentation: https://source.android.com/devices/bootloader/boot-image-header

Usage:
```sh
# ./clone_header [options] <src_img> <dst_img>
# Options: --name, --version, --cmd
#          --no-name, --no-version, --no-cmd
# Name - board name (enabled by default)
# Version - OS Patch Version (enabled by default)
# Cmd - cmdline, extra_cmdline (disabled by default)

$ ./clone_header /dev/block/by-name/boot boot.img
$ ./clone_header /dev/block/by-name/recovery recovery.img
$ ./clone_header --cmd /dev/block/by-name/recovery recovery.img
```

Downloads: https://github.com/CruelKernel/clone_header/releases
