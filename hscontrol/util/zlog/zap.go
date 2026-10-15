package zlog

import (
	"slices"

	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Zap returns a [zap.Logger] that writes to logger, for libraries that
// only log through zap.
func Zap(logger zerolog.Logger) *zap.Logger {
	return zap.New(zapCore{logger: logger})
}

type zapCore struct {
	logger zerolog.Logger
	fields []zapcore.Field
}

func (c zapCore) Enabled(level zapcore.Level) bool {
	l := zerologLevel(level)

	return l >= c.logger.GetLevel() && l >= zerolog.GlobalLevel()
}

func (c zapCore) With(fields []zapcore.Field) zapcore.Core {
	return zapCore{logger: c.logger, fields: slices.Concat(c.fields, fields)}
}

func (c zapCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checked.AddCore(entry, c)
	}

	return checked
}

func (c zapCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range slices.Concat(c.fields, fields) {
		f.AddTo(enc)
	}

	c.logger.WithLevel(zerologLevel(entry.Level)).
		Str("logger", entry.LoggerName).
		Fields(enc.Fields).
		Msg(entry.Message)

	return nil
}

func (zapCore) Sync() error { return nil }

// zerologLevel maps zap levels to zerolog. Levels above error are logged
// as errors: zerolog's WithLevel never panics or exits.
func zerologLevel(level zapcore.Level) zerolog.Level {
	switch {
	case level <= zapcore.DebugLevel:
		return zerolog.DebugLevel
	case level == zapcore.InfoLevel:
		return zerolog.InfoLevel
	case level == zapcore.WarnLevel:
		return zerolog.WarnLevel
	default:
		return zerolog.ErrorLevel
	}
}
