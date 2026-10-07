//go:build windows

package main

import "syscall"

// Affiche correctement les accents dans la console Windows.
func init() {
	syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleOutputCP").Call(65001)
}
