# tjfoc
```
1 此库源仓库是如下仓库，但是因为在做国密时使用到的国密库
https://github.com/tjfoc/gmsm
https://github.com/tjfoc/gmtls

2 为什么不用源仓库
fabric fabric-ca目录使用的是原仓库的某一个版本，但是目前无法排查到，
又在后来新开发fabric-sdk时，发现使用原仓库和fabirc-ca 中的tjfoc版本不一致，
造成验证签名失败，所以目前考虑方便，临时先开一个新仓库，方便新开发的fabric-sdk
使用，以免造成fabric-sdk使用的tjfoc原仓库，造成签名失败bug
```


# gmtls
[![Build Status](https://www.travis-ci.org/tjfoc/gmtls.svg?branch=develop)](https://www.travis-ci.org/tjfoc/gmtls)
GM TLS/SSL Based on Golang (基于国密算法的TLS/SSL代码库)


版权所有 苏州同济区块链研究院有限公司(http://www.tj-fintech.com)

Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the License for the specific language governing permissions and limitations under the License.

