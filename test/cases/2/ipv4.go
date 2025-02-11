package main

import (
	"github.com/gin-gonic/gin"
	"log"
)

func main() {
	// 创建 Gin 路由
	r := gin.Default()

	// 设置一个简单的路由
	r.GET("/", func(c *gin.Context) {
		c.String(200, "Hello, world!")
	})

	// 启动服务器并绑定到所有 IPv6 地址
	err := r.Run("[::]:8080") // 绑定到 IPv6 地址 (所有地址) 和端口 8080
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}

}
