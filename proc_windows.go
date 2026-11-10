package main

import "os/exec"

// detach на Windows не нужен: xsub там не работает, файл есть только чтобы
// на машине разработчика собирались тесты.
func detach(*exec.Cmd) {}
