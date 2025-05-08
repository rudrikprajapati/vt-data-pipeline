package models

import "time"

type VTReport struct {
	ID        string    `db:"id" json:"id"`
	Type      string    `db:"type" json:"type"`
	Data      string    `db:"data" json:"data"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

type CacheEntry struct {
	ID        string    `db:"id" json:"id"`
	Data      string    `db:"data" json:"data"`
	CachedAt  time.Time `db:"cached_at" json:"cached_at"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
}
