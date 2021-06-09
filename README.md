# AestronToken
Token generator for AestronCloud

C++

    1. Check the local environment. The C++ version of the token generation library is verified with Ubuntu 1~16.04.12 and gcc-5.4.
       Please also confirm that openssl ssl-dev has been installed or you can install with (apt install -y openssl libssl-dev). 
       检查本地环境，C++版本token生成库在ubuntu1~16.04.12  gcc-5.4版本下验证无误，清确认已安装openssl ssl-dev(apt install -y openssl libssl-dev)

    2. Go to the cpp_check_and_gen directory and execute ‘make’ to compile the test code;
       进入cpp_check_and_gen，执行make编译测试代码；

    3. Execute ‘token_d’. A series of tokens in string format will be generated and printed to the terminal.
       执行token_d，会生成一系列string格式的token打印到terminal。

    4. The example code is shown in the ‘example.cpp’ file. You can replace the ‘example.cpp’ file with your implementation code, and link with ‘libtoken.a’.
       example.cpp里面是示例代码，将example.cpp替换成您的实现代码，并链接libtoken.a。

    5. funtion genToken in the "example.cpp" file is used to generate Aestron sdk token;
       example.cpp代码中genToken用于生成Aestron sdk进频道token；
       funtion genTokenV3 in the "example.cpp" file is used to generate Aestron web sdk token;
       genTokenV3用于生成Aestron web sdk进频道token，uidstr参数需与进频道时的uidstr相同。



Java

    1. Download or clone the Aestron tokenGen repository to the local.
       将Aestron tokenGen仓库下载或克隆至本地。

    2. Open the cmd or gitbash tool, go to the  ‘java’ directory of the downloaded code, and run the ‘javac -d. *.java’ command.
       打开cmd或gitbash工具，进入下载代码java目录，运行javac -d . *.java命令。

    3. Run the ‘java sg/bigo/token/TokenUtils’ command, and the generated token will be displayed in the Terminal.
       运行java sg/bigo/token/TokenUtils命令， 生成的 Token 会显示在 Terminal 中。



Python

    1. Before starting, please make sure that Python 2 is installed and that the running environment is Python 2.
       开始前请确保已安装 Python 2，且运行环境为 Python 2。
       Download or clone the Aestron tokenGen repository to the local.
       将Aestron tokenGen仓库下载或克隆至本地。
      
    2. Open the ‘tokenGen/python/token.py’ file, and replace the appid, cert, uid, and channelName in the sample code with your own App ID, App certificate, user ID, and channel name, respectively.  
       打开 tokenGen/python/token.py文件；使用自己的 App ID、App 证书、用户 ID 以及频道名分别替换示例代码中的appid、cert、uid、channelName。
      
    3. Go to the path where the ‘RtcTokenBuilderSample.py’ file is located, and then run the following command line to generate the token. The generated token will be displayed in Terminal.
       进入 RtcTokenBuilderSample.py 所在路径，然后运行如下命令行生成 Token。 生成的 Token 会显示在 Terminal 中。

      python token.py

    4. genToken用于生成Aestron sdk进频道token；
       genTokenV3用于生成Aestron web sdk进频道token，uidstr参数需与进频道时的uidstr相同。

PHP
       
    1. Before starting, make sure you have installed the latest version of PHP.
       开始前请确保已安装最新版本的 PHP。

    2. Download or clone the Aestron tokenGen repository to the local.
       将 Aestron tokenGen仓库下载或克隆至本地。
      
    3. Open the ‘tokenGen/php/token.php’ file; replace appid, cert, uid, and channelName in the sample code with your own App ID, App certificate, user ID, and channel name respectively.
       打开 tokenGen/php/token.php 文件。使用自己的 App ID、App 证书、用户 ID 以及频道名分别替换示例代码中的appid、cert、uid、channelName。
      
    4. Go to the path where the ‘token.php’ file is located and then run the following command to generate the token. The generated token will be displayed in Terminal
       进入 token.php 所在路径，然后运行如下命令行生成 Token。 生成的 Token 会显示在 Terminal 中。
         php token.php

    5. genToken用于生成Aestron sdk进频道token；
       genTokenV3用于生成Aestron web sdk进频道token，uidstr参数需与进频道时的uidstr相同。

rust
    1. Before starting, please make sure you have installed the latest version of rust and cargo.
       开始前请确保已安装最新版本的 rust以及cargo。

    2. Download or clone the Aestron tokenGen repository to the local.
       将 Aestron tokenGen仓库下载或克隆至本地。
      
    3. Open the ‘tokenGen/rust/src/main.rs’ file; replace the values in the sample code with your own App ID, App certificate, user ID, and channel name, respectively.
       打开 tokenGen/rust/src/main.rs 文件。使用自己的 App ID、App 证书、用户 ID 以及频道名分别替换示例代码中的值。
      
    4. Go to the path where ‘tokenGen/rust/’ is located and then run the following command to generate the token. The generated token will be displayed in the terminal.
       进入 tokenGen/rust/ 所在路径，然后运行如下命令行生成 Token。 生成的 Token 会显示在 Terminal 中。

      cargo run

    5. gen_token用于生成Aestron sdk进频道token；
       gen_token_v3用于生成Aestron web sdk进频道token，uidstr参数需与进频道时的uidstr相同。


Node.js

    1. Before starting, please make sure you have installed the latest version of Node.js.
       开始前请确保已安装最新版本的Nodejs。

    2. Download or clone the Aestron tokenGen repository to the local.
       将 Aestron tokenGen仓库下载或克隆至本地。
    
    3. Open the ‘tokengen/node.js/token.js’ file; modify const CERTIFATE ='your certificate'; and fill in your own certificate.
       打开 tokengen/node.js/token.js 文件，修改 const CERTIFATE = 'your certifate'; 填入自己的证书。
            npm i crypto crc32  // install dependencies 安装 依赖包
       Create a ‘run.js’ file in the current directory
       在当前目录创建 run.js文件

            const Token= require('./token');
            const tokengen=new Token();
            console.log(`token is ${tokengen.genToken({appid:'appid',channelName:'channelName',uid:'uid'})}`)

    4. Run ‘node run.js’ to generate the token.
       运行 node run.js 生成token。



Go
       
    1. Before starting, please make sure you have installed the latest version of golang;
       开始前请确保已安装最新版本的 golang；
      
    2. Download or clone the Aestron tokenGen repository to the local.  
       将 Aestron tokenGen仓库下载或克隆至本地。
      
    3. Open the ‘tokenGen/golang/token.go’ file and then replace the values ​​in the sample code with your own App ID, App certificate, user ID, and channel name respectively.  
       打开 tokenGen/golang/token.go 文件。使用自己的 App ID、App 证书、用户 ID 以及频道名分别替换示例代码中的值。
      
    4. Go to the path where ‘tokenGen/golang/’ is located and run the following command:
       进入 tokenGen/golang/ 所在路径，运行下面命令：
           go build token.go。
      
      After running, an executable file named after “token” will be generated in the directory; run ‘./token’. The generated token will be displayed in the terminal.
      运行完成后路径下会生成名为token的可执行文件；运行./token， 生成的 Token 会显示在 Terminal 中。

    5. genToken用于生成Aestron sdk进频道token；
       genTokenV3用于生成Aestron web sdk进频道token，uidstr参数需与进频道时的uidstr相同。

Request parameters
请求参数
      
      appidStr -The App ID generated when you create the project in the Aestron Console.
      appidStr -你在 Aestron控制台创建项目时生成的 App ID。
      
      certificate -The certificate corresponding to your App ID. 
      certificate -您的appid对应的证书
      
      channelName    - The channel name. It cannot exceed 64 bytes. The following are the supported characters:
      channelName	-标识通话的频道名称，长度在 64 字节以内。以下为支持的字符集范围：
         26 lowercase English alphabets (a-z);
         26 个小写英文字母 a-z；
         26 uppercase English alphabets (A-Z);
         26 个大写应为字母 A-Z；
         10 digits (0-9);
         10 个数字 0-9；
         Space
         空格；
         "!", "#", "$", "%", "&", "(", ")", "+", "-", ":", ";", "<", "=", ".", ">", "?", "@", "[", "]", "^", "_", " {", "}", "|", "~", ","。
         
      uid - The ID of a user. It is a 64-bit unsigned integer. We recommend you use a value in the range [1, UINT64_MAX] and guarantee the uniqueness.
      uid -用户 ID，64位无符号整数。建议设置范围：1 到 UINT64_MAX，并保证唯一性。
      
      version    - The version number of the token. Currently, it is fixed as "001"；And fixed as "003" in web sdk.
      version -token的版本号，目前固定填 "001"; Web sdk 固定填"003"。
