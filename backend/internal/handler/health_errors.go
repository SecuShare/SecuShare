package handler

import "errors"

var (
	// ErrDatabaseNotInitialized is returned when the database is not initialized
	ErrDatabaseNotInitialized = errors.New("database not initialized")
	// ErrStorageNotAccessible is returned when storage is not accessible
	ErrStorageNotAccessible = errors.New("storage not accessible")
)
