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
import warnings

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
import urllib3

# Suppress InsecureRequestWarning globally (TUN mode uses IP fallback with verify=False)
# 全局禁用 InsecureRequestWarning（TUN 模式下 IP 回退需要 verify=False）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_md5(password: str, token: str) -> str:
    """
    Generate MD5 hash with HMAC for password.
    使用 HMAC 为密码生成 MD5 哈希。
    """
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()

def get_sha1(value: str) -> str:
    """
    Generate SHA1 hash for a string value.
    为字符串值生成 SHA1 哈希。
    """
    return hashlib.sha1(value.encode()).hexdigest()


def force(msg: str) -> bytes:
    """Convert string to bytes array (unused utility function)."""
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)


def ordat(msg: str, idx: int) -> int:
    """Get character code at index, return 0 if out of bounds."""
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg: str, key: bool) -> List[int]:
    """Encode string to integer array (Srun encoding algorithm)."""
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
    """Convert integer array back to string (Srun decoding algorithm)."""
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
    """Apply Srun XEncode encryption algorithm."""
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
    """HTTP Adapter for binding requests to a specific source IP address."""

    def __init__(self, source_ip: str, **kwargs):
        self.source_address = (source_ip, 0)
        super().__init__(**kwargs)

    def init_poolmanager(self, connections: int, maxsize: int,
                         block: bool = False, **pool_kwargs) -> None:
        pool_kwargs["source_address"] = self.source_address
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs):
        proxy_kwargs["source_address"] = self.source_address
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class Srun_Py:
    """
    Srun Gateway Authentication Client.
    深澜网关认证客户端。

    TUN 代理适配说明：
    - trust_env=False: 不读取系统代理环境变量
    - session.proxies 清空: 不走应用层代理
    - _make_request: 4 级回退（域名HTTPS → IP HTTPS → 域名HTTP → IP HTTP）
    - InsecureRequestWarning 已全局禁用（IP 回退时 SSL 证书不匹配不会刷屏）
    """

    def __init__(self, srun_host: str = 'gw.imust.edu.cn',
                 host_ip: str = '10.16.42.48',
                 client_ip: Optional[str] = None) -> None:
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

        # === TUN 代理适配 ===
        # 不读取系统代理环境变量（HTTP_PROXY / HTTPS_PROXY / ALL_PROXY）
        self.session.trust_env = False
        # 清空 session 级别代理设置
        self.session.proxies = {'http': '', 'https': ''}

        # 如果指定了 client_ip，绑定到该源地址
        if self.client_ip:
            adapter = SourceIPAdapter(self.client_ip)
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)

    def _make_request(self, method: str, url: str, fallback_url: str,
                      use_ip_fallback: bool = True, **kwargs) -> requests.Response:
        """
        发送 HTTP 请求，自动适配 TUN 代理环境。
        4 级回退：域名HTTPS → IP HTTPS → 域名HTTP → IP HTTP
        """
        kwargs.setdefault('timeout', (3, 10))
        last_error = None

        # 尝试1: 域名 URL + HTTPS
        try:
            return self.session.request(method, url, **kwargs)
        except Exception as e:
            last_error = e

        if use_ip_fallback:
            # 尝试2: IP URL + HTTPS（证书不匹配，verify=False）
            try:
                kwargs_fallback = {**kwargs, 'verify': False}
                return self.session.request(method, fallback_url, **kwargs_fallback)
            except Exception as e:
                last_error = e

        # 尝试3: 域名 URL + HTTP
        try:
            url_http = url.replace('https://', 'http://', 1)
            return self.session.request(method, url_http, **kwargs)
        except Exception as e:
            last_error = e

        if use_ip_fallback:
            # 尝试4: IP URL + HTTP
            try:
                fallback_url_http = fallback_url.replace('https://', 'http://', 1)
                return self.session.request(method, fallback_url_http, **kwargs)
            except Exception as e:
                last_error = e

        raise last_error

    def get_base64(self, s: str) -> str:
        """Custom base64 encoding using Srun's alphabet."""
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
        """Generate checksum for authentication."""
        chkstr = token + username
        chkstr += token + hmd5
        chkstr += token + self.ac_id
        chkstr += token + ip
        chkstr += token + self.n
        chkstr += token + self.type
        chkstr += token + i
        return chkstr

    def get_info(self, username: str, password: str, ip: str) -> str:
        """Build info string for authentication."""
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
        """Get current IP and username from gateway."""
        res = self._make_request('GET', self.get_ip_api, self.get_ip_api_ip)
        data = json.loads(res.text[res.text.find('(') + 1:-1])
        ip = data.get('client_ip') or data.get('online_ip')
        username = data.get('user_name')
        return ip, username

    def get_token(self, username: str, ip: str) -> str:
        """Get authentication token from gateway."""
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
        """Check if the client is connected to the gateway."""
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
        """Perform complex authentication work (encoding and hashing)."""
        i = self.get_info(username, password, ip)
        i = "{SRBX1}" + self.get_base64(get_xencode(i, token))
        hmd5 = get_md5(password, token)
        chksum = get_sha1(self.get_chksum(username, token, hmd5, ip, i))
        return i, hmd5, chksum

    def _parse_portal_payload(self, raw: str) -> Dict:
        """Parse raw portal response (JSON or JSONP) into a dictionary."""
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
        """Update AC ID from gateway redirect URL."""
        response = self.session.get(
            url=self.init_url.replace('https', 'http', 1),
            allow_redirects=True, timeout=(3, 10)
        )
        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)
        if 'ac_id' in query_params and len(query_params['ac_id']) > 0:
            self.ac_id = query_params['ac_id'][0]

    def login(self, username: str, password: str) -> bool:
        """Login to the gateway."""
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

        if (
            error_code in {'ok', 'logout_ok'} or
            res_code in {'ok', 'logout_ok'} or
            msg_code in {'ok', 'logout_ok'} or
            raw_res.strip().lower() in {'ok', 'logout_ok'}
        ):
            return True

        dm_res = self.logout_classic()
        dm_text = dm_res.strip().lower()
        return dm_text in {'ok', 'logout_ok', 'success', '1', 'true'}

    def logout_classic(self) -> str:
        """Logout from the gateway using DM-style."""
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
