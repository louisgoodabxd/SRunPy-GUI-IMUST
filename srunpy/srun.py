"""
Srun Authentication Module / Srun 认证模块

This module provides functionality to interact with the Srun authentication system.
本模块提供与深澜认证系统交互的功能。

Modified from: https://github.com/iskoldt-X/SRUN-authenticator
"""

import hashlib
import hmac
import json
import logging
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
import urllib3

# Suppress InsecureRequestWarning globally (TUN mode uses IP fallback with verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === 日志配置 ===
# Log to both file and console
logger = logging.getLogger('SRunPy')
logger.setLevel(logging.DEBUG)

# Console handler (INFO level)
_ch = logging.StreamHandler()
_ch.setLevel(logging.INFO)
_ch.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(_ch)

# File handler (DEBUG level) - logs to srunpy.log in the same directory as the script
_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'srunpy.log')
_fh = logging.FileHandler(_log_path, encoding='utf-8')
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(_fh)

logger.info(f'日志文件: {_log_path}')


def get_md5(password: str, token: str) -> str:
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()

def get_sha1(value: str) -> str:
    return hashlib.sha1(value.encode()).hexdigest()


def force(msg: str) -> bytes:
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)


def ordat(msg: str, idx: int) -> int:
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg: str, key: bool) -> List[int]:
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

    TUN 代理适配：
    - trust_env=False: 不读取系统代理环境变量
    - session.proxies 清空: 不走应用层代理
    - _make_request: 先尝试域名，失败后立即切 IP（短超时），避免 TUN 下长时间等待
    - InsecureRequestWarning 已全局禁用
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

        # TUN 代理适配
        self.session.trust_env = False
        self.session.proxies = {'http': '', 'https': ''}

        # 智能路由：检测域名是否可达，决定后续请求策略
        self._domain_ok = None  # None=未检测, True=域名可达, False=需要走IP

        if self.client_ip:
            adapter = SourceIPAdapter(self.client_ip)
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)

        logger.info(f'初始化完成: srun_host={srun_host}, host_ip={host_ip}, client_ip={client_ip}')

    def _detect_domain(self) -> bool:
        """
        快速检测域名是否可达（2秒超时）。
        检测一次后缓存结果，后续请求直接跳过不可达的域名。
        """
        if self._domain_ok is not None:
            return self._domain_ok

        logger.debug(f'检测域名可达性: {self.srun_host}')
        t0 = time.time()
        try:
            resp = self.session.get(
                self.get_ip_api,
                timeout=(2, 3),
                verify=False
            )
            elapsed = time.time() - t0
            self._domain_ok = True
            logger.debug(f'域名可达 ({elapsed:.1f}s): {self.srun_host}')
            return True
        except Exception as e:
            elapsed = time.time() - t0
            self._domain_ok = False
            logger.debug(f'域名不可达 ({elapsed:.1f}s): {self.srun_host} -> {type(e).__name__}')
            return False

    def _make_request(self, method: str, url: str, fallback_url: str,
                      use_ip_fallback: bool = True, **kwargs) -> requests.Response:
        """
        智能 HTTP 请求，自动适配 TUN 代理。
        - 域名可达时：直接走域名（快）
        - 域名不可达时：直接走 IP（快），跳过超时等待
        """
        # 域名首次检测
        domain_ok = self._detect_domain()

        if domain_ok:
            # 域名可达，直接走域名 HTTPS
            kwargs.setdefault('timeout', (3, 10))
            logger.debug(f'请求(域名): {method} {url[:80]}...')
            t0 = time.time()
            try:
                resp = self.session.request(method, url, **kwargs)
                logger.debug(f'请求成功 ({time.time()-t0:.1f}s)')
                return resp
            except Exception as e:
                logger.debug(f'域名请求失败 ({time.time()-t0:.1f}s): {type(e).__name__}')
                # 域名突然不可达，清除缓存，回退到 IP
                self._domain_ok = False

        # 域名不可达，直接走 IP（短超时，快速失败）
        if use_ip_fallback:
            # IP HTTPS（短超时）
            kwargs_ip = {**kwargs, 'verify': False, 'timeout': (2, 5)}
            logger.debug(f'请求(IP HTTPS): {method} {fallback_url[:80]}...')
            t0 = time.time()
            try:
                resp = self.session.request(method, fallback_url, **kwargs_ip)
                logger.debug(f'请求成功 ({time.time()-t0:.1f}s)')
                return resp
            except Exception as e:
                logger.debug(f'IP HTTPS 失败 ({time.time()-t0:.1f}s): {type(e).__name__}')

            # IP HTTP（短超时）
            fallback_url_http = fallback_url.replace('https://', 'http://', 1)
            logger.debug(f'请求(IP HTTP): {method} {fallback_url_http[:80]}...')
            t0 = time.time()
            try:
                resp = self.session.request(method, fallback_url_http, **kwargs_ip)
                logger.debug(f'请求成功 ({time.time()-t0:.1f}s)')
                return resp
            except Exception as e:
                logger.debug(f'IP HTTP 失败 ({time.time()-t0:.1f}s): {type(e).__name__}')

        raise ConnectionError(f'所有请求方式均失败: {url}')

    def get_base64(self, s: str) -> str:
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
        chkstr = token + username
        chkstr += token + hmd5
        chkstr += token + self.ac_id
        chkstr += token + ip
        chkstr += token + self.n
        chkstr += token + self.type
        chkstr += token + i
        return chkstr

    def get_info(self, username: str, password: str, ip: str) -> str:
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
        logger.debug('获取本机 IP...')
        res = self._make_request('GET', self.get_ip_api, self.get_ip_api_ip)
        data = json.loads(res.text[res.text.find('(') + 1:-1])
        ip = data.get('client_ip') or data.get('online_ip')
        username = data.get('user_name')
        logger.debug(f'本机 IP: {ip}, 用户名: {username}')
        return ip, username

    def get_token(self, username: str, ip: str) -> str:
        logger.debug(f'获取 token: username={username}, ip={ip}')
        get_challenge_params = {
            "callback": "jQuery112404953340710317169_" + str(int(time.time() * 1000)),
            "username": username,
            "ip": ip,
            "_": int(time.time() * 1000),
        }
        get_challenge_res = self._make_request(
            'GET', self.get_challenge_api, self.get_challenge_api_ip,
            params=get_challenge_params, headers=self.header
        )
        token = re.search('"challenge":"(.*?)"', get_challenge_res.text).group(1)
        logger.debug(f'Token: {token[:16]}...')
        return token

    def is_connected(self) -> Tuple[bool, bool, Optional[Dict]]:
        logger.debug('检查在线状态...')
        try:
            res = self._make_request('GET', self.get_ip_api, self.get_ip_api_ip)
            data = json.loads(res.text[res.text.find('(') + 1:-1])
            if 'error' in data and data['error'] == 'not_online_error':
                logger.debug('状态: 未在线')
                return True, False, data
            else:
                logger.debug(f'状态: 已在线 (user={data.get("user_name","?")})')
                return True, True, data
        except Exception as e:
            logger.debug(f'状态检查失败: {e}')
            return False, False, None

    def do_complex_work(self, username: str, password: str,
                        ip: str, token: str) -> Tuple[str, str, str]:
        i = self.get_info(username, password, ip)
        i = "{SRBX1}" + self.get_base64(get_xencode(i, token))
        hmd5 = get_md5(password, token)
        chksum = get_sha1(self.get_chksum(username, token, hmd5, ip, i))
        return i, hmd5, chksum

    def _parse_portal_payload(self, raw: str) -> Dict:
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
        logger.debug('更新 ac_id...')
        response = self.session.get(
            url=self.init_url.replace('https', 'http', 1),
            allow_redirects=True, timeout=(3, 10)
        )
        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)
        if 'ac_id' in query_params and len(query_params['ac_id']) > 0:
            self.ac_id = query_params['ac_id'][0]
            logger.debug(f'ac_id 更新为: {self.ac_id}')

    def login(self, username: str, password: str) -> bool:
        t_start = time.time()
        logger.info(f'开始登录: {username}')

        is_available, is_online, _ = self.is_connected()
        if not is_available or is_online:
            msg = '已在线或网络不可用' if is_online else '网络不可用'
            logger.error(f'登录失败: {msg}')
            raise Exception(f'You are already online or the network is not available!')

        self.update_acid()
        ip, _ = self.init_getip()
        token = self.get_token(username, ip)
        i, hmd5, chksum = self.do_complex_work(username, password, ip, token)

        logger.debug('发送登录请求...')
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

        elapsed = time.time() - t_start
        if data.get('error') == 'ok':
            logger.info(f'登录成功! (耗时 {elapsed:.1f}s)')
        else:
            logger.error(f'登录失败: {data.get("error")} - {data.get("error_msg", "")} (耗时 {elapsed:.1f}s)')
        return data.get('error') == 'ok'

    def logout(self) -> bool:
        t_start = time.time()
        logger.info('开始注销...')

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
            elapsed = time.time() - t_start
            logger.info(f'注销成功! (耗时 {elapsed:.1f}s)')
            return True

        logger.debug('Portal 注销未成功，尝试 DM 注销...')
        dm_res = self.logout_classic()
        dm_text = dm_res.strip().lower()
        elapsed = time.time() - t_start
        if dm_text in {'ok', 'logout_ok', 'success', '1', 'true'}:
            logger.info(f'注销成功 (DM)! (耗时 {elapsed:.1f}s)')
        else:
            logger.error(f'注销失败: {dm_text} (耗时 {elapsed:.1f}s)')
        return dm_text in {'ok', 'logout_ok', 'success', '1', 'true'}

    def logout_classic(self) -> str:
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
