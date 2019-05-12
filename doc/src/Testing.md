# Testing

* Describe test framework


## Real Hardware

Build produces an uefi.img FAT32 file that can be loaded on real hardware.

Settings on iDRAC
COM2 or COM1 should work

ssh <idrac ip>
console com2

Ctrl+\ to exit


Boot controls:
Set to Virtual Floppy

Map virtual media: Select ISO file, attach uefi.img

Then reboot