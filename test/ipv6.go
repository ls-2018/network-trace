package main

import (
	"github.com/gin-gonic/gin"
	"log"
	"os"
	"os/exec"
	"time"
)

func main() {
	// 创建 Gin 路由
	r := gin.Default()

	// 设置一个简单的路由
	r.GET("/", func(c *gin.Context) {
		c.String(200, "Hello, IPv6 world!")
	})

	go func() {
		time.Sleep(5 * time.Second)
		exec.Command("curl", "-6", "http://[fe80::20c:29ff:fed6:6fbc%eth1]:8080").Run()

		os.Exit(0)
	}()

	// 启动服务器并绑定到所有 IPv6 地址
	err := r.Run("[::]:8080") // 绑定到 IPv6 地址 (所有地址) 和端口 8080
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}

}
