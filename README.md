# AestronToken
Token generator for AestronCloud

C++

   1. 检查本地环境，C++版本token生成库在ubuntu1~16.04.12  gcc-5.4版本下验证无误，清确认已安装openssl ssl-dev(apt install -y openssl libssl-dev)

   2. 进入cpp_check_and_gen，执行make编译测试代码；

   3. 执行token_d，会生成一系列string格式的token打印到terminal。

   4. example.cpp里面是示例代码，将example.cpp替换成您的实现代码，并链接libtoken.a。



Java

   1.将Aestron tokenGen仓库下载或克隆至本地。

   2.打开cmd或gitbash工具，进入下载代码java目录，运行javac -d . *.java命令。

   3.运行java sg/bigo/token/TokenUtils命令， 生成的 Token 会显示在 Terminal 中。



Python

      开始前请确保已安装 Python 2，且运行环境为 Python 2。

      将Aestron tokenGen仓库下载或克隆至本地。
      
      打开 tokenGen/python/token.py文件；使用自己的 App ID、App 证书、用户 ID 以及频道名分别替换示例代码中的appid、cert、uid、channelName。
      
      进入 RtcTokenBuilderSample.py 所在路径，然后运行如下命令行生成 Token。 生成的 Token 会显示在 Terminal 中。

      python token.py


PHP
       
      开始前请确保已安装最新版本的 PHP。

      将 Aestron tokenGen仓库下载或克隆至本地。
      
      打开 tokenGen/php/token.php 文件。使用自己的 App ID、App 证书、用户 ID 以及频道名分别替换示例代码中的appid、cert、uid、channelName。
      
      进入 token.php 所在路径，然后运行如下命令行生成 Token。 生成的 Token 会显示在 Terminal 中。
      php token.php


rust
      开始前请确保已安装最新版本的 rust以及cargo。

      将 Aestron tokenGen仓库下载或克隆至本地。
      
      打开 tokenGen/rust/src/main.rs 文件。使用自己的 App ID、App 证书、用户 ID 以及频道名分别替换示例代码中的值。
      
      进入 tokenGen/rust/ 所在路径，然后运行如下命令行生成 Token。 生成的 Token 会显示在 Terminal 中。

      cargo run



Node.js

       开始前请确保已安装最新版本的Nodejs。

      将 Aestron tokenGen仓库下载或克隆至本地。
      打开 tokengen/node.js/token.js 文件，修改 const CERTIFATE = 'your certifate'; 填入自己的证书。
            npm i crypto crc32   安装 依赖包
      在当前目录创建 run.js文件

            const Token= require('./token');
            const tokengen=new Token();
            console.log(`token is ${tokengen.genToken({appid:'appid',channelName:'channelName',uid:'uid'})}`)
      运行 node run.js 生成token



Go
       
      开始前请确保已安装最新版本的 golang；
      
      将 Aestron tokenGen仓库下载或克隆至本地。
      
      打开 tokenGen/golang/token.go 文件。使用自己的 App ID、App 证书、用户 ID 以及频道名分别替换示例代码中的值。
      
      进入 tokenGen/golang/ 所在路径，运行下面命令 go build token.go
      
      运行完成后路径下会生成名为token的可执行文件；运行./token， 生成的 Token 会显示在 Terminal 中。

请求参数
      
      appidStr	-你在 Aestron控制台创建项目时生成的 App ID。
      
      certifate -您的appid对应的证书
      
      channelName	-标识通话的频道名称，长度在 64 字节以内。
         以下为支持的字符集范围：
         26 个小写英文字母 a-z；
         26 个大写应为字母 A-Z；
         10 个数字 0-9；
         空格；
         "!", "#", "$", "%", "&", "(", ")", "+", "-", ":", ";", "<", "=", ".", ">", "?", "@", "[", "]", "^", "_", " {", "}", "|", "~", ","。
         
      uid -用户 ID，64位无符号整数。建议设置范围：1 到 (264-1)，并保证唯一性。
      
      version -token的版本号，目前固定填 "001"
