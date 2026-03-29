// Package profiling provides pprof middleware for development mode
package profiling

import (
	"net/http"
	"net/http/pprof"

	"github.com/gin-gonic/gin"
)

// DevelopmentHandler returns the pprof handler for development mode
func DevelopmentHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
	mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	return mux
}

// WrapGin wraps the pprof handler for use with Gin
func WrapGin() gin.HandlerFunc {
	handler := DevelopmentHandler()
	return func(c *gin.Context) {
		handler.ServeHTTP(c.Writer, c.Request)
	}
}

// RegisterWithEngine registers all pprof routes with a Gin engine
func RegisterWithEngine(engine *gin.Engine, isDevelopment bool) {
	if !isDevelopment {
		return
	}

	engine.GET("/debug/pprof/", gin.WrapH(http.HandlerFunc(pprof.Index)))
	engine.GET("/debug/pprof/cmdline", gin.WrapH(http.HandlerFunc(pprof.Cmdline)))
	engine.GET("/debug/pprof/profile", gin.WrapH(http.HandlerFunc(pprof.Profile)))
	engine.POST("/debug/pprof/symbol", gin.WrapH(http.HandlerFunc(pprof.Symbol)))
	engine.GET("/debug/pprof/symbol", gin.WrapH(http.HandlerFunc(pprof.Symbol)))
	engine.GET("/debug/pprof/trace", gin.WrapH(http.HandlerFunc(pprof.Trace)))

	engine.GET("/debug/pprof/heap", gin.WrapH(pprof.Handler("heap")))
	engine.GET("/debug/pprof/goroutine", gin.WrapH(pprof.Handler("goroutine")))
	engine.GET("/debug/pprof/block", gin.WrapH(pprof.Handler("block")))
	engine.GET("/debug/pprof/mutex", gin.WrapH(pprof.Handler("mutex")))
	engine.GET("/debug/pprof/allocs", gin.WrapH(pprof.Handler("allocs")))
	engine.GET("/debug/pprof/threadcreate", gin.WrapH(pprof.Handler("threadcreate")))
}
