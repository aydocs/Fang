package main

import (
	"context"
	"embed"
	_ "github.com/aydocs/fang/modules"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "Fang - Web Application Security Scanner",
		Width:     1280,
		Height:    800,
		MinWidth:  960,
		MinHeight: 600,

		AssetServer: &assetserver.Options{
			Assets: assets,
		},

		OnStartup:  app.Startup,
		OnShutdown: app.Shutdown,

		Bind: []interface{}{
			app,
		},

		BackgroundColour: &options.RGBA{R: 10, G: 10, B: 15, A: 255},
		OnBeforeClose: func(ctx context.Context) bool {
			return false
		},
	})

	if err != nil {
		panic(err)
	}
}
