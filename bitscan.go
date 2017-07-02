package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/whats-this/cdn-origin/weed"

	log "github.com/Sirupsen/logrus"
	"github.com/buaazp/fasthttprouter"
	"github.com/dchest/uniuri"
	"github.com/sheenobu/go-clamscan"
	"github.com/spf13/viper"
	"github.com/valyala/fasthttp"
)

// currentAPIVersion represents the current API base path.
const currentAPIBasePath = "/v1"

// version is the current version of bitscan.
const version = "0.1.0"

// folderFileMode is the default file mode for the temporary file directory.
const folderFileMode os.FileMode = os.ModeDir | 0770

// objectFileMode is the default file mode for objects stored in the temporary file directory.
const objectFileMode os.FileMode = 0660

// applicationJSON is the JSON header prefix expected on routes that consume JSON data.
const applicationJSON = "application/json"

// contentType is the content type header to read request content type from.
const contentType = "Content-Type"

// attachment represents a Slack webhook attachment.
type attachment struct {
	Fallback string `json:"fallback"`
	Color    string `json:"color"`
	Title    string `json:"title"`
	Text     string `json:"text"`
}

// object represents a bitbin object.
type object struct {
	BucketKey     string  `json:"bucket_key"`
	Bucket        string  `json:"bucket"`
	Key           string  `json:"key"`
	Dir           string  `json:"dir"`
	Type          uint8   `json:"type"`
	BackendFileID *string `json:"backend_file_id"`
	DestURL       *string `json:"dest_url"`
	ContentType   *string `json:"content_type"`
	ContentLength *uint   `json:"content_length"`
	AuthHash      *string `json:"auth_hash"`
	CreatedAt     *string `json:"created_at"`
	MD5Hash       *string `json:"md5_hash"`
}

func init() {
	// http.listenAddress (string=":8080"): TCP address to listen to for HTTP requests
	viper.SetDefault("http.listenAddress", ":8080")
	viper.BindEnv("HTTP_LISTEN_ADDRESS", "http.listenAddress")

	// log.debug (bool=false): enable debug mode (logs requests and prints other information)
	viper.SetDefault("log.debug", false)
	viper.BindEnv("log.debug", "DEBUG")

	// notifications.slackWebhookURL (string=""): optional webhook URL for Slack-compatible notification messages
	// (error + positive files)
	viper.SetDefault("notifications.slackWebhookURL", "")
	viper.BindEnv("SLACK_WEBHOOK_URL", "notifications.slackWebhookURL")

	// seaweed.masterURL* (string): SeaweedFS master URL
	viper.SetDefault("seaweed.masterURL", "http://localhost:9333")
	viper.BindEnv("SEAWEED_MASTER_URL", "seaweed.masterURL")

	// Configuration file settings
	viper.SetConfigType("toml")
	viper.SetConfigName("bitscan")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/bitscan/")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.WithField("err", err).Fatal("failed to read in configuration")
		}
	}

	// Enable debug mode
	if viper.GetBool("log.debug") {
		log.SetLevel(log.DebugLevel)
	}
}

// httpClient to use for webhook requests.
var httpClient = &http.Client{
	Jar:     nil,
	Timeout: time.Minute * 5,
}

// seaweed client to use for fetching files from the SeaweedFS cluster.
var seaweed *weed.Seaweed

// tmpDir is the directory used for storing downloaded files before they are scanned.
var tmpDir string

func main() {
	var err error

	// Attempt to connect to SeaweedFS master
	seaweed = weed.New(viper.GetString("seaweed.masterURL"), time.Second*5)
	err = seaweed.Ping()
	if err != nil {
		log.WithField("err", err).Fatal("failed to ping SeaweedFS master")
		return
	}

	// Create router
	router := &fasthttprouter.Router{
		RedirectTrailingSlash:  true,
		RedirectFixedPath:      true,
		HandleMethodNotAllowed: true,
		HandleOPTIONS:          true,
		NotFound: func(ctx *fasthttp.RequestCtx) {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetContentType("application/json; charset=utf-8")
			fmt.Fprint(ctx, `{"code":404,"message":"Not Found"}`)
		},
		MethodNotAllowed: func(ctx *fasthttp.RequestCtx) {
			ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
			ctx.SetContentType("application/json; charset=utf-8")
			fmt.Fprint(ctx, `{"code":405,"message":"Method Not Allowed"}`)
		},
		PanicHandler: func(ctx *fasthttp.RequestCtx, err interface{}) {
			log.WithField("err", err).Error("recovered panic while serving request")
			ctx.ResetBody()
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetContentType("application/json; charset=utf-8")
			fmt.Fprint(ctx, `{"code":500,"message":"Internal Server Error"}`)
		},
	}

	// Apply routes

	// > GET / (index)
	router.GET("/", func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetContentType("application/json; charset=utf-8")
		ctx.Response.Header.Set("Location", currentAPIBasePath)
		fmt.Fprintf(ctx, `{"code":200,"message":"index","current":"%s"}`, currentAPIBasePath)
	})

	// > POST /scanObject.async (scanObject.async)
	// Scan a file, expects a file object to be supplied.
	// Scans are run asynchronously on this route, and 201 Accepted responses are returned immediately.
	// If a virus is detected, a Slack webhook is fired.
	// TODO: automatically delete files and clear Varnish cache (?)
	router.POST("/v1/scanObject.async", func(ctx *fasthttp.RequestCtx) {
		ctx.SetContentType("application/json; charset=utf-8")

		// Check Content-Type
		if !strings.HasPrefix(string(ctx.Request.Header.Peek(contentType)), applicationJSON) {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			fmt.Fprint(ctx, `{"code":400,"message":"Bad Request (Content-Type not JSON)"}`)
			return
		}

		// Parse request body
		data := &object{}
		err := json.Unmarshal(ctx.PostBody(), data)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			fmt.Fprint(ctx, `{"code":400,"message":"Bad Request (could not parse JSON body)"}`)
			return
		}

		// Verify request body
		if data.Type != 0 {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			fmt.Fprint(ctx, `{"code":400,"message":"Bad Request (invalid object type)"}`)
			return
		}

		// Scan asynchronously and return response
		go processScan(data)
		ctx.SetStatusCode(fasthttp.StatusAccepted)
		fmt.Fprint(ctx, `{"code":201,"message":"Accepted (processing asynchronously)"}`)
	})

	// Serve
	server := &fasthttp.Server{
		Handler:      router.Handler,
		Name:         "bitscan/" + version,
		ReadTimeout:  time.Minute * 3,
		WriteTimeout: time.Minute * 30,
		LogAllErrors: log.GetLevel() == log.DebugLevel,
		Logger:       log.New(),
	}

	log.Info("Attempting to listen on " + viper.GetString("http.listenAddress"))
	if err := server.ListenAndServe(viper.GetString("http.listenAddress")); err != nil {
		log.WithField("err", err).Fatal("error in ListenAndServe")
	}
}

// getTempFilename returns a filename with the supplied extension (ext should have period).
func getTempFilename(ext string) (string, error) {
	if tmpDir == "" {
		tmpDir = os.TempDir() + "/bitscan_" + uniuri.New()
	}

	// Check if directory exists, otherwise create new directory
	info, err := os.Stat(tmpDir)
	if err != nil || !info.IsDir() {
		tmpDir = os.TempDir() + "/bitscan_" + uniuri.New()
		err = os.Mkdir(tmpDir, folderFileMode)
		if err != nil {
			log.WithField("err", err).Error("failed to generate temporary directory")
			return "", err
		}
	}

	return tmpDir + "/" + uniuri.New() + ext, nil
}

// sendWebhook to the Slack endpoint in the configuration.
func sendWebhook(title, text, color string) error {
	if viper.GetString("notifications.slackWebhookURL") == "" {
		return nil
	}

	d, err := json.Marshal(map[string][]attachment{
		"attachments": {
			{
				Fallback: fmt.Sprintf("**%s**\n%s", title, text),
				Color:    color,
				Title:    title,
				Text:     text,
			},
		},
	})
	if err != nil {
		return err
	}

	_, err = httpClient.Post(viper.GetString("notifications.slackWebhookURL"), applicationJSON, bytes.NewBuffer(d))
	return err
}

func processScan(object *object) error {
	res, err := scan(object)
	if err != nil {
		err = sendWebhook(
			fmt.Sprintf("Error scanning `%s`", object.BucketKey),
			fmt.Sprintf("```\n%s```", err),
			"danger")
		if err != nil {
			log.WithField("err", err).Error("failed to invoke webhook")
		}
		return err
	}
	if res.Error != nil {
		err = sendWebhook(
			fmt.Sprintf("Error scanning `%s`", object.BucketKey),
			fmt.Sprintf("```\n%s```", res.Error),
			"danger")
		if err != nil {
			log.WithField("err", err).Error("failed to invoke webhook")
		}
		return err
	}

	if res.Found {
		log.WithFields(log.Fields{
			"bucket_key": object.BucketKey,
			"virus":      res.Virus,
			"md5_hash":   object.MD5Hash,
		}).Info("found virus in a file")
		err = sendWebhook(fmt.Sprintf("Positive file found: `%s`", object.BucketKey),
			fmt.Sprintf("`%s` (`%s`) returned positive during scan with virus `%s`.\n\n"+
				"It has not been deleted from storage backend.", object.BucketKey, object.MD5Hash,
				res.Virus),
			"#439FE0")
		if err != nil {
			log.WithField("err", err).Error("failed to invoke webhook")
		}
		return err
	}

	return nil
}

func scan(object *object) (*clamscan.Result, error) {
	path, err := getTempFilename(path.Ext(object.Key))
	if err != nil {
		return nil, err
	}

	// Create temporary file
	file, err := os.Create(path)
	if err != nil {
		log.WithFields(log.Fields{
			"err":  err,
			"path": path,
		}).Error("failed to create temporary file")
		return nil, errors.New("failed to create temporary file: " + err.Error())
	}
	file.Chmod(objectFileMode)

	// Get file from SeaweedFS
	_, err = seaweed.Get(file, *object.BackendFileID, "")
	if err != nil {
		log.WithFields(log.Fields{
			"err":  err,
			"path": path,
		}).Error("failed to get file from SeaweedFS backend")
		return nil, errors.New("failed to get file from SeaweedFS backend: " + err.Error())
	}

	res, err := clamscan.Scan(&clamscan.Options{}, path)
	if err != nil {
		log.WithFields(log.Fields{
			"err":  err,
			"path": path,
		}).Error("failed to scan file")
		return nil, errors.New("failed to scan file: " + err.Error())
	}

	return <-res, nil
}
