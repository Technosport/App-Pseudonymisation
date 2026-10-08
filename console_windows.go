//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// Configure la console Windows : encodage UTF-8 et activation des couleurs ANSI.
func init() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	kernel32.NewProc("SetConsoleOutputCP").Call(65001)

	const (
		stdOutputHandle                 = ^uintptr(10) // STD_OUTPUT_HANDLE = ((DWORD)-11)
		enableVirtualTerminalProcessing = 0x0004
	)
	hOut, _, _ := kernel32.NewProc("GetStdHandle").Call(stdOutputHandle)
	if hOut != 0 && hOut != uintptr(syscall.InvalidHandle) {
		var mode uint32
		getConsoleMode := kernel32.NewProc("GetConsoleMode")
		setConsoleMode := kernel32.NewProc("SetConsoleMode")
		r, _, _ := getConsoleMode.Call(hOut, uintptr(unsafe.Pointer(&mode)))
		if r != 0 {
			setConsoleMode.Call(hOut, uintptr(mode|enableVirtualTerminalProcessing))
		}
	}
}
