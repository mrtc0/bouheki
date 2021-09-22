package logger

import (
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	Logger *log.Entry
)

func init() {
	Logger = NewLogger()
}

func NewLogger() *log.Entry {
	logLevel := os.Getenv("BOUHEKI_LOG")
	switch logLevel {
	case "TRACE":
		log.SetLevel(log.TraceLevel)
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
	case "INFO":
		log.SetLevel(log.InfoLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
	return log.WithFields(log.Fields{"pid": os.Getpid()})
}

func SetFormatter(format string) {
	switch format {
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	case "text":
		log.SetFormatter(&log.TextFormatter{})
	default:
		log.SetFormatter(&log.JSONFormatter{})
	}
}

func SetOutput(path string) {
	if path == "stdout" || path == "" {
		Logger.Logger.Out = os.Stdout
	} else {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			Logger.Fatal(err)
		}
		Logger.Logger.Out = file
	}
}

func SetRotation(path string, maxSize, maxAge int) {
	if path == "stdout" || path == "" {
		return
	}

	log.SetOutput(&lumberjack.Logger{
		Filename: path,
		MaxSize:  maxSize,
		MaxAge:   maxAge,
	})
}

func Fatal(err error) {
	Logger.Fatal(err)
}

func Debug(message string) {
	Logger.Debug(message)
}

func Info(message string) {
	Logger.Info(message)
}

func Error(err error) {
	Logger.Error(err)
}

func WithFields(fields log.Fields) *log.Entry {
	return log.WithFields(fields)
}
