package webassets

import (
	"embed"
	"io/fs"
)

//go:embed all:public
var files embed.FS

func Files() fs.FS { f, _ := fs.Sub(files, "public"); return f }
