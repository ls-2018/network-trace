<!--
Node1: (a1 -> b1 -> c1 )
Node2: (a2 -> b2 -> c2 -> b2 -> d2)
c1 -> a2
Node1 Node2 使用方框包起来,方框随着节点拖动，大小动态变化，方框和节点都可以拖动
圆角方框,并设置 标签

a1,a2,b1,b2,c1,c2,d2 使用图片
https://kubernetes.io/icons/favicon-a1.png
https://kubernetes.io/icons/favicon-a2.png
https://kubernetes.io/icons/favicon-b1.png
https://kubernetes.io/icons/favicon-b2.png
https://kubernetes.io/icons/favicon-c1.png
https://kubernetes.io/icons/favicon-c2.png
https://kubernetes.io/icons/favicon-d2.png
图片大小 30*30

不使用双向箭头，连接线标号
连接线 用曲线,是虚线, 用彩色的移动的点表示,连接线上用1,2,3,4,5,6,7,8 进行标识, 提示信息是向下的

根据以上信息,使用 d3.js 绘制出节点和边，绘制一个动态图，箭头是动态的, 可以拖动

使node 按照 列排布, 同一个node 的节点上下排布

-->
