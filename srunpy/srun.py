"""
Srun Authentication Module / Srun 认证模块

This module provides functionality to interact with the Srun authentication system.
本模块提供与深澜认证系统交互的功能。

Modified from: https://github.com/iskoldt-X/SRUN-authenticator
"""

import hashlib
import hmac
import json
import math
import os
import re
import socket
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager


def get_md5(password: str, token: str) -> str:
    """
    Generate MD5 hash with HMAC for password.
    使用 HMAC 为密码生成 MD5 哈希。

    Args / 参数:
        password: User password / 用户密码
        token: Authentication token / 认证令牌

    Returns / 返回:
        MD5 hash string / MD5 哈希字符串
    """
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()

def get_sha1(value: str) -> str:
    """
    Generate SHA1 hash for a string value.
    为字符串值生成 SHA1 哈希。

    Args / 参数:
        value: Input string / 输入字符串

    Returns / 返回:
        SHA1 hash string / SHA1 哈希字符串
    """
    return hashlib.sha1(value.encode()).hexdigest()


def force(msg: str) -> bytes:
    """
    Convert string to bytes array (unused utility function).
    将字符串转换为字节数组（未使用的工具函数）。

    Args / 参数:
        msg: Input string / 输入字符串

    Returns / 返回:
        Bytes representation / 字节表示
    """
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)


def ordat(msg: str, idx: int) -> int:
    """
    Get character code at index, return 0 if out of bounds.
    获取索引处的字符代码，如果越界则返回 0。

    Args / 参数:
        msg: Input string / 输入字符串
        idx: Index position / 索引位置

    Returns / 返回:
        Character code or 0 / 字符代码或 0
    """
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg: str, key: bool) -> List[int]:
    """
    Encode string to integer array (Srun encoding algorithm).
    将字符串编码为整数数组（深澜编码算法）。

    Args / 参数:
        msg: Message to encode / 要编码的消息
        key: Whether to append length / 是否追加长度

    Returns / 返回:
        List of encoded integers / 编码整数列表
    """
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd


def lencode(msg: List[int], key: bool) -> Optional[str]:
    """
    Convert integer array back to string (Srun decoding algorithm).
    将整数数组转换回字符串（深澜解码算法）。

    Args / 参数:
        msg: List of integers to decode / 要解码的整数列表
        key: Whether length was appended / 是否追加了长度

    Returns / 返回:
        Decoded string or None / 解码的字符串或 None
    """
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return None
        ll = m
    for i in range(0, l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
            msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
    if key:
        return "".join(msg)[0:ll]
    return "".join(msg)


def get_xencode(msg: str, key: str) -> str:
    """
    Apply Srun XEncode encryption algorithm.
    应用深澜 XEncode 加密算法。

    Args / 参数:
        msg: Message to encode / 要编码的消息
        key: Encryption key / 加密密钥

    Returns / 返回:
        Encoded string / 编码后的字符串
    """
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)


class SourceIPAdapter(HTTPAdapter):
    """
    HTTP Adapter for binding requests to a specific source IP address.
    用于将请求绑定到特定源 IP 地址的 HTTP 适配器。
    """

    def __init__(self, source_ip: str, **kwargs):
        """
        Initialize the adapter with source IP.
        使用源 IP 初始化适配器。

        Args / 参数:
            source_ip: Source IP address to bind / 要绑定的源 IP 地址
            **kwargs: Additional arguments for HTTPAdapter / HTTPAdapter 的额外参数
        """
        self.source_address = (source_ip, 0)
        super().__init__(**kwargs)

    def init_poolmanager(self, connections: int, maxsize: int,
                         block: bool = False, **pool_kwargs) -> None:
        """
        Initialize pool manager with source address.
        使用源地址初始化池管理器。
        """
        pool_kwargs["source_address"] = self.source_address
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs):
        """
        Initialize proxy manager with source address.
        使用源地址初始化代理管理器。
        """
        proxy_kwargs["source_address"] = self.source_address
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def _detect_physical_interface_ip() -> Optional[str]:
    """
    Detect the physical network interface IP by connecting to a non-routable
    address and checking which local IP is used.
    通过连接一个不可路由地址来检测物理网络接口的本地IP。

    This helps bypass TUN proxy by identifying the real physical interface IP.
    这有助于绕过 TUN 代理，识别真实的物理接口 IP。

    Returns / 返回:
        Local IP address or None / 本地 IP 地址或 None
    """
    candidates = set()

    # Method 1: UDP connect to detect routing (no actual traffic sent)
    # 方法1: UDP 连接检测路由（不发送实际流量）
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.connect(("198.51.100.1", 80))
            candidates.add(s.getsockname()[0])
    except (OSError, socket.timeout):
        pass

    # Method 2: Get all non-loopback IPv4 addresses
    # 方法2: 获取所有非回环 IPv4 地址
    try:
        hostname = socket.gethostname()
        for addr in socket.gethostbyname_ex(hostname)[2]:
            if not addr.startswith("127."):
                candidates.add(addr)
    except socket.gaierror:
        pass

    # Method 3: getaddrinfo
    # 方法3: getaddrinfo
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET):
            addr = info[4][0]
            if not addr.startswith("127."):
                candidates.add(addr)
    except socket.gaierror:
        pass

    # Prefer 10.x.x.x addresses (campus network range)
    # 优先选择 10.x.x.x 地址（校园网范围）
    campus_ips = [ip for ip in candidates if ip.startswith("10.")]
    if campus_ips:
        return campus_ips[0]
    return sorted(candidates)[0] if candidates else None


class Srun_Py:
    """
    Srun Gateway Authentication Client.
    深澜网关认证客户端。

    This class handles authentication with Srun gateway systems.
    该类处理与深澜网关系统的认证。
    """

    def __init__(self, srun_host: str = 'gw.imust.edu.cn',
                 host_ip: str = '10.16.42.48',
                 client_ip: Optional[str] = None) -> None:
        """
        Initialize Srun client.
        初始化深澜客户端。

        Args / 参数:
            srun_host: Gateway hostname / 网关主机名
            host_ip: Gateway IP address / 网关 IP 地址
            client_ip: Client IP address to bind (optional) / 要绑定的客户端 IP（可选）
        """
        self.srun_host = srun_host
        self.host_ip = host_ip
        self.init_url = f"https://{srun_host}"
        self.get_ip_api = f'https://{srun_host}/cgi-bin/rad_user_info?callback=JQuery'
        self.get_ip_api_ip = f'https://{host_ip}/cgi-bin/rad_user_info?callback=JQuery'
        self.get_challenge_api = f"https://{srun_host}/cgi-bin/get_challenge"
        self.get_challenge_api_ip = f"https://{host_ip}/cgi-bin/get_challenge"
        self.srun_portal_api = f"https://{srun_host}/cgi-bin/srun_portal"
        self.srun_portal_api_ip = f"https://{host_ip}/cgi-bin/srun_portal"
        self.rad_user_dm_api = f"https://{srun_host}/cgi-bin/rad_user_dm"
        self.rad_user_dm_api_ip = f"https://{host_ip}/cgi-bin/rad_user_dm"
        self.header = {
            'Host': srun_host,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0'
        }
        self.n = '200'
        self.type = '1'
        self.ac_id = '6'
        self.enc = "srun_bx1"
        self._ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
        self.client_ip = client_ip
        self.session = requests.Session()

        # === TUN 代理兼容性优化 ===
        # 禁用 session 读取系统代理环境变量（HTTP_PROXY / HTTPS_PROXY / ALL_PROXY）
        # Disable session from reading system proxy env vars
        self.session.trust_env = False
        # 清空 session 级别的代理设置
        # Clear session-level proxy settings
        self.session.proxies = {
            'http': '',
            'https': '',
        }

        # 如果指定了 client_ip，绑定到该源地址
        # If client_ip is specified, bind to that source address
        if self.client_ip:
            adapter = SourceIPAdapter(self.client_ip)
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)
        else:
            # 自动检测物理网卡 IP 并绑定，绕过 TUN 接口
            # Auto-detect physical NIC IP and bind, bypassing TUN interface
            detected_ip = _detect_physical_interface_ip()
            if detected_ip:
                self.detected_ip = detected_ip
                adapter = SourceIPAdapter(detected_ip)
                self.session.mount('http://', adapter)
                self.session.mount('https://', adapter)
            else:
                self.detected_ip = None

    def _make_request(self, method: str, url: str, fallback_url: str,
                      use_ip_fallback: bool = True, **kwargs) -> requests.Response:
        """
        Make an HTTP request with TUN proxy bypass and fallback strategy.
        发送 HTTP 请求，支持 TUN 代理绕过和回退策略。

        Strategy / 策略:
        1. Try domain URL first (https) / 先尝试域名 URL（https）
        2. Fall back to IP URL (https) / 回退到 IP URL（https）
        3. Fall back to domain URL (http) / 回退到域名 URL（http）
        4. Fall back to IP URL (http) / 回退到 IP URL（http）

        Args / 参数:
            method: HTTP method / HTTP 方法
            url: Primary URL (domain-based) / 主 URL（基于域名）
            fallback_url: Fallback URL (IP-based) / 回退 URL（基于 IP）
            use_ip_fallback: Whether to try IP fallback / 是否尝试 IP 回退
            **kwargs: Additional arguments for requests / requests 的额外参数

        Returns / 返回:
            Response object / 响应对象

        Raises / 抛出:
            requests.RequestException: If all attempts fail / 如果所有尝试都失败
        """
        # Set a reasonable timeout to avoid hanging on TUN-intercepted connections
        # 设置合理的超时时间，避免 TUN 拦截的连接挂起
        kwargs.setdefault('timeout', (3, 10))  # (connect_timeout, read_timeout)

        # Disable SSL verification for IP-based URLs (certificate won't match)
        # 对 IP URL 禁用 SSL 验证（证书不匹配）
        last_error = None

        # Attempt 1: Domain URL with HTTPS
        # 尝试1: 域名 URL + HTTPS
        try:
            return self.session.request(method, url, **kwargs)
        except Exception as e:
            last_error = e

        if use_ip_fallback:
            # Attempt 2: IP URL with HTTPS (verify=False for cert mismatch)
            # 尝试2: IP URL + HTTPS（证书不匹配，verify=False）
            try:
                kwargs_fallback = {**kwargs, 'verify': False}
                return self.session.request(method, fallback_url, **kwargs_fallback)
            except Exception as e:
                last_error = e

        # Attempt 3: Domain URL with HTTP
        # 尝试3: 域名 URL + HTTP
        try:
            url_http = url.replace('https://', 'http://', 1)
            return self.session.request(method, url_http, **kwargs)
        except Exception as e:
            last_error = e

        if use_ip_fallback:
            # Attempt 4: IP URL with HTTP
            # 尝试4: IP URL + HTTP
            try:
                fallback_url_http = fallback_url.replace('https://', 'http://', 1)
                return self.session.request(method, fallback_url_http, **kwargs)
            except Exception as e:
                last_error = e

        raise last_error

    def get_base64(self, s: str) -> str:
        """
        Custom base64 encoding using Srun's alphabet.
        使用深澜的字母表进行自定义 base64 编码。

        Args / 参数:
            s: String to encode / 要编码的字符串

        Returns / 返回:
            Encoded string / 编码后的字符串
        """
        r = []
        x = len(s) % 3
        if x:
            s = s + '\0' * (3 - x)
        for i in range(0, len(s), 3):
            d = s[i:i + 3]
            a = ord(d[0]) << 16 | ord(d[1]) << 8 | ord(d[2])
            r.append(self._ALPHA[a >> 18])
            r.append(self._ALPHA[a >> 12 & 63])
            r.append(self._ALPHA[a >> 6 & 63])
            r.append(self._ALPHA[a & 63])
        if x == 1:
            r[-1] = '='
            r[-2] = '='
        if x == 2:
            r[-1] = '='
        return ''.join(r)

    def get_chksum(self, username: str, token: str, hmd5: str,
                   ip: str, i: str) -> str:
        """
        Generate checksum for authentication.
        生成认证校验和。

        Args / 参数:
            username: Username / 用户名
            token: Authentication token / 认证令牌
            hmd5: MD5 hash / MD5 哈希
            ip: IP address / IP 地址
            i: Info string / 信息字符串

        Returns / 返回:
            SHA1 checksum / SHA1 校验和
        """
        chkstr = token + username
        chkstr += token + hmd5
        chkstr += token + self.ac_id
        chkstr += token + ip
        chkstr += token + self.n
        chkstr += token + self.type
        chkstr += token + i
        return chkstr

    def get_info(self, username: str, password: str, ip: str) -> str:
        """
        Build info string for authentication.
        构建认证信息字符串。

        Args / 参数:
            username: Username / 用户名
            password: Password / 密码
            ip: IP address / IP 地址

        Returns / 返回:
            JSON info string / JSON 信息字符串
        """
        info_temp = {
            "username": username,
            "password": password,
            "ip": ip,
            "acid": self.ac_id,
            "enc_ver": self.enc
        }
        i = re.sub("'", '"', str(info_temp))
        i = re.sub(" ", '', i)
        return i

    def init_getip(self) -> Tuple[str, Optional[str]]:
        """
        Get current IP and username from gateway.
        从网关获取当前 IP 和用户名。

        Returns / 返回:
            Tuple of (IP address, username) / (IP 地址, 用户名) 的元组
        """
        res = self._make_request('GET', self.get_ip_api, self.get_ip_api_ip)
        data = json.loads(res.text[res.text.find('(') + 1:-1])
        ip = data.get('client_ip') or data.get('online_ip')
        username = data.get('user_name')
        return ip, username

    def get_token(self, username: str, ip: str) -> str:
        """
        Get authentication token from gateway.
        从网关获取认证令牌。

        Args / 参数:
            username: Username / 用户名
            ip: IP address / IP 地址

        Returns / 返回:
            Authentication token / 认证令牌
        """
        get_challenge_params = {
            "callback": (
                "jQuery112404953340710317169_" +
                str(int(time.time() * 1000))
            ),
            "username": username,
            "ip": ip,
            "_": int(time.time() * 1000),
        }
        get_challenge_res = self._make_request(
            'GET', self.get_challenge_api, self.get_challenge_api_ip,
            params=get_challenge_params, headers=self.header
        )
        token = re.search('"challenge":"(.*?)"', get_challenge_res.text).group(1)
        return token

    def is_connected(self) -> Tuple[bool, bool, Optional[Dict]]:
        """
        Check if the client is connected to the gateway.
        检查客户端是否连接到网关。

        Returns / 返回:
            Tuple of (is_available, is_online, data) /
            (是否可用, 是否在线, 数据) 的元组
        """
        try:
            res = self._make_request('GET', self.get_ip_api, self.get_ip_api_ip)
            data = json.loads(res.text[res.text.find('(') + 1:-1])
            if 'error' in data and data['error'] == 'not_online_error':
                return True, False, data
            else:
                return True, True, data
        except Exception:
            return False, False, None

    def do_complex_work(self, username: str, password: str,
                        ip: str, token: str) -> Tuple[str, str, str]:
        """
        Perform complex authentication work (encoding and hashing).
        执行复杂的认证工作（编码和哈希）。

        Args / 参数:
            username: Username / 用户名
            password: Password / 密码
            ip: IP address / IP 地址
            token: Authentication token / 认证令牌

        Returns / 返回:
            Tuple of (info, hmd5, chksum) / (信息, MD5哈希, 校验和) 的元组
        """
        i = self.get_info(username, password, ip)
        i = "{SRBX1}" + self.get_base64(get_xencode(i, token))
        hmd5 = get_md5(password, token)
        chksum = get_sha1(self.get_chksum(username, token, hmd5, ip, i))
        return i, hmd5, chksum

    def _parse_portal_payload(self, raw: str) -> Dict:
        """
        Parse raw portal response (JSON or JSONP) into a dictionary.
        将门户原始响应（JSON 或 JSONP）解析为字典。

        Args / 参数:
            raw: Raw response text / 原始响应文本

        Returns / 返回:
            Parsed payload dictionary / 解析后的载荷字典
        """
        text = (raw or '').strip()
        if not text:
            return {}
        try:
            return json.loads(text)
        except Exception:
            pass
        start = text.find('(')
        end = text.rfind(')')
        if start != -1 and end > start:
            body = text[start + 1:end].strip()
            try:
                return json.loads(body)
            except Exception:
                return {}
        return {}

    def update_acid(self) -> None:
        """
        Update AC ID from gateway redirect URL.
        从网关重定向 URL 更新 AC ID。
        """
        response = self.session.get(
            url=self.init_url.replace('https', 'http', 1),
            allow_redirects=True, timeout=(3, 10)
        )
        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)
        if 'ac_id' in query_params and len(query_params['ac_id']) > 0:
            self.ac_id = query_params['ac_id'][0]

    def login(self, username: str, password: str) -> bool:
        """
        Login to the gateway.
        登录到网关。

        Args / 参数:
            username: Username / 用户名
            password: Password / 密码

        Returns / 返回:
            True if login successful / 登录成功返回 True

        Raises / 抛出:
            Exception: If already online or network not available /
                      如果已在线或网络不可用
        """
        is_available, is_online, _ = self.is_connected()
        if not is_available or is_online:
            raise Exception('You are already online or the network is not available!')
        self.update_acid()
        ip, _ = self.init_getip()
        token = self.get_token(username, ip)
        i, hmd5, chksum = self.do_complex_work(username, password, ip, token)
        srun_portal_params = {
            'callback': 'jQuery11240645308969735664_' + str(int(time.time() * 1000)),
            'action': 'login',
            'username': username,
            'password': '{MD5}' + hmd5,
            'ac_id': self.ac_id,
            'ip': ip,
            'chksum': chksum,
            'info': i,
            'n': self.n,
            'type': self.type,
            'os': 'windows+10',
            'name': 'windows',
            'double_stack': '0',
            '_': int(time.time() * 1000)
        }
        srun_portal_res = self._make_request(
            'GET', self.srun_portal_api, self.srun_portal_api_ip,
            params=srun_portal_params, headers=self.header
        )
        srun_portal_res = srun_portal_res.text
        data = json.loads(srun_portal_res[srun_portal_res.find('(') + 1:-1])
        return data.get('error') == 'ok'

    def logout(self) -> bool:
        is_available, is_online, _ = self.is_connected()
        if not is_available or not is_online:
            raise Exception('You are not online or the network is not available!')

        # Align with login flow: refresh AC ID before portal logout.
        # 与登录流程对齐：注销前刷新 AC ID。
        try:
            self.update_acid()
        except Exception:
            pass

        ip, username = self.init_getip()
        params = {
            "action": "logout",
            "username": username,
            "ip": ip,
            "ac_id": self.ac_id
        }
        raw_res = ''
        try:
            raw_res = self._make_request(
                'GET', self.srun_portal_api, self.srun_portal_api_ip,
                params=params, headers=self.header
            ).text
        except Exception:
            raw_res = ''

        payload = self._parse_portal_payload(raw_res)
        error_code = str(payload.get('error', '')).lower()
        res_code = str(payload.get('res', '')).lower()
        msg_code = str(payload.get('error_msg', '')).lower()

        # Compatible with different gateway return shapes.
        # 兼容不同网关返回结构。
        if (
            error_code in {'ok', 'logout_ok'} or
            res_code in {'ok', 'logout_ok'} or
            msg_code in {'ok', 'logout_ok'} or
            raw_res.strip().lower() in {'ok', 'logout_ok'}
        ):
            return True

        # Fallback to DM-style logout when portal logout did not clearly succeed.
        # 当 portal 注销未明确成功时，回退到 DM 风格注销。
        dm_res = self.logout_classic()
        dm_text = dm_res.strip().lower()
        return dm_text in {'ok', 'logout_ok', 'success', '1', 'true'}

    def logout_classic(self) -> str:
        """
        Logout from the gateway.
        从网关注销。

        Returns / 返回:
            True if logout successful / 注销成功返回 True

        Raises / 抛出:
            Exception: If not online or network not available /
                      如果未在线或网络不可用
        """
        ip, username = self.init_getip()
        t = int(time.time() * 1000)
        sign = get_sha1(str(t) + username + ip + '0' + str(t))
        user_dm_params = {
            'ip': ip,
            'username': username,
            'time': t,
            'unbind': 0,
            'sign': sign
        }
        user_dm_res = self._make_request(
            'GET', self.rad_user_dm_api, self.rad_user_dm_api_ip,
            params=user_dm_params, headers=self.header
        )
        user_dm_res = user_dm_res.text
        return user_dm_res
