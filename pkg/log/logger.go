package logger

import (
	"os"

	"github.com/sirupsen/logrus"
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
	return log.WithFields(log.Fields{"bouheki_pid": os.Getpid()})
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

func SetLabel(labels map[string]string) {
	for k, v := range labels {
		Logger = Logger.WithFields(log.Fields{k: v})
	}
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

type LogLabels struct {
	Labels map[string]string
}

type AuditEventLog struct {
	Action     string
	Hostname   string
	PID        uint32
	Comm       string
	ParentComm string
}

type RestrictedNetworkLog struct {
	AuditEventLog
	Addr     string
	Domain   string
	Port     uint16
	Protocol string
}

type RestrictedFileAccessLog struct {
	AuditEventLog
	Path string
}

type RestrictedMountLog struct {
	AuditEventLog
	SourcePath string
}

func (l *RestrictedNetworkLog) Info() {
	Logger.WithFields(logrus.Fields{
		"Action":     l.Action,
		"Hostname":   l.Hostname,
		"PID":        l.PID,
		"Comm":       l.Comm,
		"ParentComm": l.ParentComm,
		"Addr":       l.Addr,
		"Domain":     l.Domain,
		"Port":       l.Port,
		"Protocol":   l.Protocol,
	}).Info("Traffic is trapped in the filter.")
}

func (l *RestrictedFileAccessLog) Info() {
	Logger.WithFields(logrus.Fields{
		"Action":     l.Action,
		"Hostname":   l.Hostname,
		"PID":        l.PID,
		"Comm":       l.Comm,
		"ParentComm": l.ParentComm,
		"Path":       l.Path,
	}).Info("File access is trapped in th filter.")
}

func (l *RestrictedMountLog) Info() {
	Logger.WithFields(logrus.Fields{
		"Action":     l.Action,
		"Hostname":   l.Hostname,
		"PID":        l.PID,
		"Comm":       l.Comm,
		"ParentComm": l.ParentComm,
		"SourcePath": l.SourcePath,
	}).Info("Mount event is trapped in th filter.")
}
