# CryptoToolbox - 加解密工具箱

一个基于 Flask 的 Web 加解密工具箱，支持多种加密/解密、编码/解码、哈希算法，方便团队日常使用。

## 支持算法

| 分类 | 算法 | 操作 |
|------|------|------|
| 对称加密 | AES-128-CBC, AES-256-CBC, 3DES-CBC, RC4, SM4-CBC | 加密 / 解密 |
| 编码 | Base64, URL编码, Hex编码 | 编码 / 解码 |
| 哈希 | MD5, SHA-1, SHA-256, SHA-512, SHA-3-256, HMAC-SHA256 | 单向哈希 |
| 密码哈希 | bcrypt | 哈希 / 验证 |

## 快速开始

```bash
pip install -r requirements.txt
python app.py
```

浏览器打开 http://localhost:5000

## 功能特点

- 亮色 / 暗色双主题切换
- 密钥输入支持显示 / 隐藏
- 输入输出一键交换
- 结果一键复制
- 对称加密自动生成随机 IV，密钥通过 SHA-256 派生
- `Ctrl+Enter` 快捷执行

## 项目结构

```
├── app.py              # Flask 主应用
├── crypto_engine.py    # 加解密引擎
├── _sm4.py             # SM4 国密算法实现
├── requirements.txt    # Python 依赖
└── templates/
    └── index.html      # 前端页面
```

## Contributor

- [DanderlionJer](https://github.com/DanderlionJer)
