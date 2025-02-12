package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/ClickHouse/clickhouse-go/v2/lib/proto"
	"net"
	"time"
)

var conn driver.Conn

func init() {
	// 设置 ClickHouse 的连接参数
	CONN, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{"localhost:9000"}, // 使用 native 接口的端口号
		Auth: clickhouse.Auth{
			Database: "test", // 如果需要认证，设置数据库名和用户名密码等
			Username: "root",
			Password: "123456",
		},
		DialContext: func(ctx context.Context, addr string) (net.Conn, error) {
			fmt.Println("dial")
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		//Debug: true,
		//Debugf: func(format string, v ...any) {
		//	fmt.Printf(format+"\n", v...)
		//},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
			"enable_json_type":   1,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		DialTimeout:          time.Second * 30,
		MaxOpenConns:         5,
		MaxIdleConns:         5,
		ConnMaxLifetime:      time.Duration(10) * time.Minute,
		ConnOpenStrategy:     clickhouse.ConnOpenInOrder,
		BlockBufferSize:      10,
		MaxCompressionBuffer: 10240,
		ClientInfo: clickhouse.ClientInfo{ // optional, please see Client info section in the README.md
			Products: []struct {
				Name    string
				Version string
			}{
				{Name: "my-app", Version: "0.1"},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	if err := CONN.Ping(context.Background()); err != nil {
		var exception *clickhouse.Exception
		if errors.As(err, &exception) {
			fmt.Printf("Exception [%d] %s \n%s\n", exception.Code, exception.Message, exception.StackTrace)
		}
		panic(err)
	}
	fmt.Println("connected to ClickHouse")
	conn = CONN
}
func CheckMinServerVersion(conn driver.Conn, major, minor, patch uint64) bool {
	v, err := conn.ServerVersion()
	if err != nil {
		panic(err)
	}
	return proto.CheckMinVersion(proto.Version{
		Major: major,
		Minor: minor,
		Patch: patch,
	}, v.Version)
}
func JSONPathsExample() error {
	ctx := context.Background()

	if !CheckMinServerVersion(conn, 24, 9, 0) {
		fmt.Print("unsupported clickhouse version for JSON type")
		return nil
	}

	err := conn.Exec(ctx, "DROP TABLE IF EXISTS go_json_example")
	if err != nil {
		return err
	}

	err = conn.Exec(ctx, `
	CREATE TABLE go_json_example (product JSON) ENGINE=Memory
	`)
	if err != nil {
		return err
	}

	batch, err := conn.PrepareBatch(ctx, "INSERT INTO go_json_example (product)")
	if err != nil {
		return err
	}

	insertProduct := clickhouse.NewJSON()
	insertProduct.SetValueAtPath("id", clickhouse.NewDynamicWithType(uint64(1234), "UInt64"))
	insertProduct.SetValueAtPath("name", "Book")
	insertProduct.SetValueAtPath("tags", []string{"library", "fiction"})
	insertProduct.SetValueAtPath("pricing.price", int64(750))
	insertProduct.SetValueAtPath("pricing.currency", "usd")
	insertProduct.SetValueAtPath("metadata.region", "us")
	insertProduct.SetValueAtPath("metadata.page_count", int64(852))
	insertProduct.SetValueAtPath("created_at", clickhouse.NewDynamicWithType(time.Now().UTC().Truncate(time.Millisecond), "DateTime64(3)"))

	if err = batch.Append(insertProduct); err != nil {
		return err
	}

	if err = batch.Send(); err != nil {
		return err
	}

	var selectedProduct clickhouse.JSON

	if err = conn.QueryRow(ctx, "SELECT product FROM go_json_example").Scan(&selectedProduct); err != nil {
		return err
	}

	fmt.Printf("inserted product: %+v\n", insertProduct)
	fmt.Printf("selected product: %+v\n", selectedProduct)
	return nil
}

func main() {
	fmt.Println(JSONPathsExample())
}
