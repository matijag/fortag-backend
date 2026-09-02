package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type databaseLock struct {
	file *os.File
}

func acquireDatabaseLock(dbPath string, shared bool) (*databaseLock, error) {
	lockPath := dbPath + ".lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open database lock %s: %w", lockPath, err)
	}
	operation := unix.LOCK_EX | unix.LOCK_NB
	mode := "exclusive"
	if shared {
		operation = unix.LOCK_SH | unix.LOCK_NB
		mode = "shared"
	}
	if err := unix.Flock(int(file.Fd()), operation); err != nil {
		file.Close()
		return nil, fmt.Errorf("acquire %s database lock %s: %w", mode, lockPath, err)
	}
	return &databaseLock{file: file}, nil
}

func (lock *databaseLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return fmt.Errorf("unlock database: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close database lock: %w", closeErr)
	}
	return nil
}
