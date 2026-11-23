package recording

import "errors"

// Refusals of a playback (plan.md Contract); internal/httpapi maps them.
var (
	ErrNotPlayable  = errors.New("recording: not an SSH terminal session")
	ErrTooLarge     = errors.New("recording: too large to play here")
	ErrNotFound     = errors.New("recording: not found")
	ErrAccessDenied = errors.New("recording: the management identity cannot read session recordings")
	ErrExpired      = errors.New("recording: playback expired")
	ErrBusy         = errors.New("recording: too many playbacks")
)
