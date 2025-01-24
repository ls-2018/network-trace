package gin

import (
	"fmt"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func Run() {
	r := gin.Default()

	// CORS middleware with custom configuration
	corsConfig := cors.Config{
		AllowOrigins:  []string{"*"},                                        // 允许的来源
		AllowMethods:  []string{"GET", "POST", "PUT", "DELETE"},             // 允许的HTTP方法
		AllowHeaders:  []string{"Origin", "Content-Length", "Content-Type"}, // 允许的请求头
		ExposeHeaders: []string{"Content-Length"},                           // 允许的响应头
		MaxAge:        12 * time.Hour,                                       // 预检请求的缓存时间
	}
	r.Use(cors.New(corsConfig))
	// 设置模板文件目录
	r.LoadHTMLGlob("templates/*")

	// 设置静态文件目录
	r.Static("/static", "./static")
	r.GET("/", func(c *gin.Context) {
		fmt.Println("index")
		c.HTML(200, "index.html", nil)
	})

	r.GET("/api/nodes", func(c *gin.Context) {
		c.JSON(200, gin.H{"data": []string{"a1", "a2", "b1", "b2", "c1", "c2", "d2"}})
	})

	r.GET("/api/namespaces", func(c *gin.Context) {
		c.JSON(200, gin.H{"data": []string{"a1", "a2", "b1", "b2", "c1", "c2", "d2"}})
	})

	r.GET("/api/namespace/:namespace/pods", func(c *gin.Context) {
		c.JSON(200, gin.H{"data": []string{"a1", "a2", "b1", "b2", "c1", "c2", "d2"}})
	})

	r.GET("/links", func(c *gin.Context) {
		c.JSON(200, gin.H{"data": links})
	})
	r.GET("/points", func(c *gin.Context) {
		c.JSON(200, gin.H{"data": points})
	})
	r.Run(":8000") // 在默认的8080端口运行
}

// 定义结构体
type Point struct {
	Name  string `json:"name"`
	Group int    `json:"group"`
	Img   string `json:"img"`
}

var points = []Point{
	{Name: "a1", Group: 1, Img: "./static/img/pod.webp"},
	{Name: "b1", Group: 1, Img: "./static/img/svc.webp"},
	{Name: "c1", Group: 1, Img: "./static/img/k8s.png"},
	{Name: "a2", Group: 2, Img: "./static/img/iptables.jpg"},
	{Name: "b2", Group: 2, Img: "./static/img/flannel.png"},
	{Name: "c2", Group: 2, Img: "./static/img/istio.png"},
	{Name: "d2", Group: 2, Img: "./static/img/envoy.png"},
	{Name: "e2", Group: 2, Img: "./static/img/calico.png"},
	{Name: "f2", Group: 2, Img: "./static/img/cilium.png"},
}

type Link struct {
	Source  string `json:"source"`
	Target  string `json:"target"`
	Index   int    `json:"index"`
	Success bool   `json:"success"`
}

var links = []Link{
	{Source: "a1", Target: "b1", Index: 1, Success: true},
	{Source: "b1", Target: "c1", Index: 2, Success: true},
	{Source: "c1", Target: "a2", Index: 3, Success: false},
	{Source: "a2", Target: "b2", Index: 4, Success: true},
	{Source: "b2", Target: "c2", Index: 5, Success: true},
	{Source: "c2", Target: "b2", Index: 6, Success: true},
	{Source: "b2", Target: "d2", Index: 7, Success: true},
	{Source: "d2", Target: "e2", Index: 8, Success: true},
	{Source: "e2", Target: "f2", Index: 9, Success: true},
}
