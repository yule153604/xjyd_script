"""
仅供学习交流：本脚本仅用于 Python 爬虫技术学习与交流，请勿用于任何商业用途或非法目的。
账号风险：使用自动化工具可能违反服务商的用户协议，存在账号被限制或封禁的风险。使用本脚本产生的任何后果由使用者自行承担。
数据安全：脚本仅在本地运行，不会上传任何用户数据。但在使用过程中请注意保护好自己的 Cookie 和 Token 等敏感信息，切勿泄露给他人。
停止更新：作者保留随时停止维护或删除本项目的权利。
1. xunbao (维语寻宝app和微信小程序双端) - 每日签到 3/7/10/15 =0/0/2/10
2. ydcj (maxrap10086公众号抽奖) - 每天自动抽奖-3次
3. xj10086_gzh (公众号权益中心) - 每天签到 7/14/21/28 = 1/2/5/10
使用库：asyncio, httpx
"""

import asyncio
import base64
import random
import ssl
import urllib.parse
from datetime import datetime, timedelta
from dataclasses import dataclass

import httpx
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


# ==================== 用户配置区域 (请在此处填入你的信息) ====================

#未配置cookie时候请转到main函数(529行左右)内将任务注释掉

# 1. 寻宝任务配置
# 填入手机号(不太需要)和抓取的 Cookie
# 抓取说明:
# - 打开 "新疆移动" APP -> 首页切换维语版 -> 寻宝 -> 抓取任意请求的 Cookie(https://wap.xj.10086.cn/uyservice/server/xunBaoAct/xunBaoActivityNew/init)
# - 微信公众号 "maxrap10086" -> 右下 -> 寻宝 -> 抓取任意请求的 Cookie(同上)
# 注意区分 APP 渠道和微信渠道的 User-Agent 和 Cookie
# 支持多个账号，复制下面的账号块并修改内容即可
XUNBAO_ACCOUNTS = [
    # 账号 1: APP 渠道
    {
        "name": "APP渠道",
        "mobile": "你的手机号",
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148/wkwebview leadeon/12.0.1/CMCCIT",
        "initial_cookie": "你的APP_Cookie"
    },

    # 账号 2: 微信渠道
    {
        "name": "微信渠道",
        "mobile": "你的手机号",
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.54(0x1800363a) NetType/WIFI Language/zh_CN",
        "initial_cookie": "你的微信_Cookie"
    }
]

# 2. 抽奖任务配置 (maxrap10086公众号)
# 将下面的 YDCJ_COOKIE 键值对填入你的抓取内容
# 抓取说明:
# - 关注 "maxrap10086" 微信公众号 -> 左侧第一个 -> 进入活动页面
# - 抓取 wx.10086.cn 域名的请求 Cookie(https://wx.10086.cn/qwhdhub/lottery/remain)
YDCJ_COOKIE = "你的抽奖Cookie"
YDCJ_BASE_URL = "https://wx.10086.cn/qwhdhub"
YDCJ_ACTIVITY_ID = "1025112950"


# 3. 权益中心任务配置           
#将下面的 GZH_COOKIES 键值对填入你的抓取内容
# 抓取说明:
# - 关注 "新疆移动权益超市" 微信公众号 -> 中间第二个 -> 签到领18
# 或直接浏览器打开链接: https://wap.xj.10086.cn/quanyi/micro-page/everyDay.html
# - 抓取 wap.xj.10086.cn 域名的请求 Cookie (https://wap.xj.10086.cn/quanyi/earnBenefits/initPage)
GZH_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-SG,zh;q=0.9,en-SG;q=0.8,en;q=0.7,zh-CN;q=0.6",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Origin": "https://wap.xj.10086.cn",
    "Pragma": "no-cache",
    "Referer": "https://wap.xj.10086.cn/quanyi/micro-page/everyDay.html",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    "X-Requested-with": "XMLHttpRequest",
    "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

GZH_COOKIES = {
    "gdp_user_id": "",
    "9e4e5fa7244c6b6e_gdp_user_key": "",
    "9e4e5fa7244c6b6e_gdp_session_id": "",
    "pathId": "",
    "_zw_kvani5r": "",
    "yxfk_token": "",
    "USER_TOKEN": "",
    "mobile": "",
}


# ==================== 通用日志工具 ====================

def log_info(message: str) -> None:
    """打印信息日志"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] {message}")


def log_success(message: str) -> None:
    """打印成功日志"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [✓] {message}")


def log_error(message: str) -> None:
    """打印错误日志"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [✗] {message}")


def log_warning(message: str) -> None:
    """打印警告日志"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [⚠] {message}")


def log_task(task_name: str, message: str) -> None:
    """打印任务日志"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [{task_name}] {message}")


# ==================== 寻宝任务配置 (常量) ====================

# RSA 公钥（用于加密请求参数）
XUNBAO_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCf6u6tKSnHB4OMc2gNsfBi15KUhMlT5jrSdsNXgwGOO6MAnSIXYdZTWJb6z4Vmp4Bm27L2RCr/TDriDGuCLuewfHEyo4PZ6rtLz2F0NRObePLF39NeYSdhTQD4Gh2w9f/NCeGXLnjnltVaMCTX0t5DM8KeKS+QesI1UtVivRfRkQIDAQAB
-----END PUBLIC KEY-----"""


# ==================== 权益中心任务配置 (常量) ====================

@dataclass(frozen=True)
class GZHEndpoints:
    """权益中心 API 接口地址"""
    BASE_URL: str = "https://wap.xj.10086.cn/quanyi/earnBenefits"

    @property
    def init_page(self) -> str:
        return f"{self.BASE_URL}/initPage"

    @property
    def sign_in(self) -> str:
        return f"{self.BASE_URL}/signIn"

    @property
    def draw(self) -> str:
        return f"{self.BASE_URL}/draw"

    @property
    def browse_gzh(self) -> str:
        return f"{self.BASE_URL}/browseGzhPage"

    @property
    def browse_xcx(self) -> str:
        return f"{self.BASE_URL}/browseXcxPage"

    @property
    def cumulative_signin(self) -> str:
        return f"{self.BASE_URL}/cumulativeSignin"


# 累计签到奖励映射
CUMULATIVE_REWARD_MAP = {7: "12", 14: "22", 21: "32", 28: "42"}
GZH_TARGET_COUNT = 3  # 公众号浏览任务目标次数
XCX_TARGET_COUNT = 5  # 小程序浏览任务目标次数


# ==================== 通用常量 ====================

HEARTBEAT_MIN_SECONDS = 900   # 15分钟
HEARTBEAT_MAX_SECONDS = 1200  # 20分钟


# ==================== 寻宝任务实现 ====================

def rsa_encrypt(plain_text: str) -> str | None:
    """RSA 加密并 URL 编码"""
    try:
        key = RSA.import_key(XUNBAO_PUBLIC_KEY)
        cipher = PKCS1_v1_5.new(key)
        encrypted_bytes = cipher.encrypt(plain_text.encode('utf-8'))
        b64_str = base64.b64encode(encrypted_bytes).decode('utf-8')
        return urllib.parse.quote(b64_str)
    except Exception:
        return None


def parse_cookie_string(cookie_str: str) -> dict:
    """解析 Cookie 字符串为字典"""
    cookies = {}
    for item in cookie_str.split(';'):
        if '=' in item:
            k, v = item.strip().split('=', 1)
            cookies[k] = v
    return cookies


async def xunbao_account_task(client: httpx.AsyncClient, config: dict) -> None:
    """单个寻宝账号的心跳任务"""
    name = config['name']

    if "你的" in config['initial_cookie']:
        log_task(f"寻宝-{name}", "请先配置 Cookie")
        return

    cookies = parse_cookie_string(config['initial_cookie'])
    headers = {
        'Host': 'wap.xj.10086.cn',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
        'Accept-Language': 'zh-CN,zh-Hans;q=0.9',
        'User-Agent': config['ua'],
        'Referer': 'https://wap.xj.10086.cn/uyservice/activity/xunbao/index.html',
    }

    base_url = "https://wap.xj.10086.cn/uyservice/server"
    last_sign_date = ""

    #log_task(f"寻宝-{name}", "启动守护进程...")

    while True:
        try:
            # 心跳请求
            enc_param = rsa_encrypt("shareId=null&shareCode=null")
            if not enc_param:
                log_task(f"寻宝-{name}", "加密失败")
                await asyncio.sleep(60)
                continue

            params = {
                'param': enc_param,
                'ajaxSubmitType': 'post',
                'ajax_randomcode': str(random.random())
            }

            response = await client.get(
                f"{base_url}/xunBaoAct/xunBaoActivityNew/init",
                headers=headers,
                cookies=cookies,
                params=params,
                timeout=15
            )
            res = response.json()

            if res.get('X_RESULTCODE') == '0':
                # 心跳成功，检查是否需要签到
                sign_count = int(res.get('userSignCount', 0))
                today = datetime.now().date().isoformat()

                if last_sign_date != today:
                    #log_task(f"寻宝-{name}", f"新的一天 ({today})，执行签到...")
                    next_day = sign_count + 1

                    # 根据签到天数选择签到 ID
                    sign_id = 99
                    if next_day in [3, 7, 10, 15]:
                        sign_id = {3: 0, 7: 1, 10: 2, 15: 3}[next_day]

                    # 执行签到
                    enc_sign = rsa_encrypt(f"Id={sign_id}")
                    if enc_sign:
                        sign_params = {
                            'param': enc_sign,
                            'ajaxSubmitType': 'post',
                            'ajax_randomcode': str(random.random())
                        }
                        sign_resp = await client.get(
                            f"{base_url}/xunBaoAct/xunBaoActivityNew/sign_insert",
                            headers=headers,
                            cookies=cookies,
                            params=sign_params,
                            timeout=15
                        )
                        log_task(f"寻宝-{name}", f"签到结果: {sign_resp.json()}")
                        last_sign_date = today

            elif res.get('X_RESULTCODE') == 'noLogin':
                log_task(f"寻宝-{name}", "Cookie 已失效！")
                break
            else:
                log_task(f"寻宝-{name}", f"心跳异常: {res}")

        except Exception as e:
            log_task(f"寻宝-{name}", f"请求异常: {e}")

        # 随机等待 15-20 分钟
        sleep_time = random.randint(HEARTBEAT_MIN_SECONDS, HEARTBEAT_MAX_SECONDS)
        await asyncio.sleep(sleep_time)


async def xunbao_task() -> None:
    """寻宝任务主协程 - 管理所有账号"""
    async with httpx.AsyncClient() as client:
        tasks = []
        for config in XUNBAO_ACCOUNTS:
            tasks.append(xunbao_account_task(client, config))
            await asyncio.sleep(5)  # 错开启动时间

        if tasks:
            await asyncio.gather(*tasks)


# ==================== 抽奖任务实现 ====================

async def ydcj_task() -> None:
    """抽奖任务主协程"""

    if "你的" in YDCJ_COOKIE:
        log_task("抽奖", "请先配置 Cookie")
        return

    headers = {
        "Host": "wx.10086.cn",
        "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.54(0x1800363a) NetType/WIFI Language/zh_CN",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://wx.10086.cn",
        "Referer": f"{YDCJ_BASE_URL}/turntable/{YDCJ_ACTIVITY_ID}",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh-Hans;q=0.9",
        "Cookie": YDCJ_COOKIE
    }

    # 创建自定义 SSL 上下文（使用更宽松的密码套件）
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    try:
        ssl_context.set_ciphers("DEFAULT:@SECLEVEL=1")  # 尝试降低安全级别
    except Exception:
        pass  # Windows 可能不支持，忽略

    #log_task("抽奖", "启动守护进程...")
    error_count = 0

    async with httpx.AsyncClient(verify=ssl_context, timeout=30) as client:
        while True:
            try:
                # 查询剩余抽奖次数（心跳）
                response = await client.post(
                    f"{YDCJ_BASE_URL}/lottery/remain",
                    headers=headers,
                    json={}
                )
                result = response.json()

                if result.get("code") != "SUCCESS":
                    error_count += 1
                    log_task("抽奖", f"查询失败 (第{error_count}次)")
                    if error_count >= 5:
                        log_task("抽奖", "连续失败多次，请更新Cookie")
                        break
                else:
                    error_count = 0
                    remain = result.get("data", 0)

                    if remain and remain > 0:
                        log_task("抽奖", f"检测到 {remain} 次抽奖机会")

                        # 执行抽奖
                        for i in range(1, remain + 1):
                            draw_resp = await client.get(
                                f"{YDCJ_BASE_URL}/lottery/lotterySafely",
                                headers=headers
                            )
                            draw_result = draw_resp.json()

                            if draw_result.get("code") == "SUCCESS" and draw_result.get("success"):
                                prize_data = draw_result.get("data", {})
                                prize_name = prize_data.get("prizeName", "未知奖品")
                                log_task("抽奖", f"第 {i} 次中奖: {prize_name}")
                            else:
                                msg = draw_result.get("msg", "")
                                log_task("抽奖", f"第 {i} 次抽奖: {msg}")
                                if "机会" in msg or "不足" in msg or "次数" in msg:
                                    break

                            if i < remain:
                                await asyncio.sleep(random.randint(3, 6))

            except Exception as e:
                log_task("抽奖", f"运行异常: {e}")

            # 随机等待 15-20 分钟
            sleep_time = random.randint(HEARTBEAT_MIN_SECONDS, HEARTBEAT_MAX_SECONDS)
            await asyncio.sleep(sleep_time)


# ==================== 权益中心任务实现 ====================

async def gzh_post_request(
    client: httpx.AsyncClient,
    url: str,
    task_name: str = "",
    silent: bool = False,
) -> dict | None:
    """权益中心 POST 请求"""
    try:
        response = await client.post(
            url,
            cookies=GZH_COOKIES,
            headers=GZH_HEADERS,
        )
        result = response.json()

        if not silent and task_name:
            log_task(task_name, str(result))

        return result
    except Exception as e:
        log_error(f"请求失败 [{task_name}]: {e}")
        return None


async def run_xj10086_gzh_daily() -> None:
    """执行一次权益中心每日任务"""
    if "你的" in str(GZH_COOKIES):
         log_task("权益中心", "请先配置 Cookie")
         return

    api = GZHEndpoints()

    #log_task("权益中心", "开始执行每日任务...")

    async with httpx.AsyncClient(timeout=30) as client:
        # 1. 初始化页面
        init_data = await gzh_post_request(client, api.init_page, "初始化", silent=True)

        if not init_data or "data" not in init_data:
            log_error("权益中心初始化失败")
            return

        data = init_data["data"]
        browse_xcx_count = data.get("browseXcxCount", 0)
        browse_gzh_count = data.get("browseGzhCount", 0)
        sign_count = data.get("signInCount", 0)

        #log_task("权益中心", f"小程序已浏览: {browse_xcx_count}/{XCX_TARGET_COUNT}")
        #log_task("权益中心", f"公众号已浏览: {browse_gzh_count}/{GZH_TARGET_COUNT}")

        xcx_remaining = max(0, XCX_TARGET_COUNT - browse_xcx_count)
        gzh_remaining = max(0, GZH_TARGET_COUNT - browse_gzh_count)

        # 2. 每日签到 + 首次抽奖
        sign_result = await gzh_post_request(client, api.sign_in, "每日签到", silent=True)
        if sign_result:
            log_task("每日签到", f'message: "{sign_result.get("message", "未知")}"')

        draw_result = await gzh_post_request(client, api.draw, "抽奖_1", silent=True)
        if draw_result:
            prize_data = draw_result.get("data", {})
            if isinstance(prize_data, dict):
                log_task("抽奖_1", f'prizeName: "{prize_data.get("prizeName", "未知")}"')

        # 3. 检查累计签到奖励
        log_task("权益中心", f"当前累计签到天数: {sign_count}")
        if sign_count in CUMULATIVE_REWARD_MAP:
            group_id = CUMULATIVE_REWARD_MAP[sign_count]
            files = {"groupId": (None, group_id)}
            try:
                resp = await client.post(
                    api.cumulative_signin,
                    headers=GZH_HEADERS,
                    cookies=GZH_COOKIES,
                    files=files,
                )
                result = resp.json()
                if result.get("success"):
                    log_success(f"累计签到 {sign_count} 天奖励领取成功！")
                else:
                    log_warning(f"领奖失败: {result.get('message', '')}")
            except Exception as e:
                log_error(f"领奖请求异常: {e}")

        # 4. 浏览任务
        if gzh_remaining > 0 or xcx_remaining > 0:
            log_task("权益中心", f"执行浏览任务: 公众号 {gzh_remaining} 次, 小程序 {xcx_remaining} 次")

            browse_tasks = []
            for i in range(gzh_remaining):
                browse_tasks.append(gzh_post_request(client, api.browse_gzh, f"公众号浏览_{i+1}"))
            for i in range(xcx_remaining):
                browse_tasks.append(gzh_post_request(client, api.browse_xcx, f"小程序浏览_{i+1}"))

            await asyncio.gather(*browse_tasks)

            # 5. 额外抽奖
            extra_draw_count = (1 if xcx_remaining > 0 else 0) + (1 if gzh_remaining > 0 else 0)
            for i in range(extra_draw_count):
                result = await gzh_post_request(client, api.draw, f"抽奖_{i+2}", silent=True)
                if result:
                    prize_data = result.get("data", {})
                    if isinstance(prize_data, dict):
                        log_task(f"抽奖_{i+2}", f'prizeName: "{prize_data.get("prizeName", "未知")}"')

        log_task("权益中心", "每日任务执行完成")


async def xj10086_gzh_task() -> None:
    """权益中心任务主协程 - 每天执行一次"""
    while True:
        # 执行今日任务
        await run_xj10086_gzh_daily()

        # 计算到明天 8:00 的秒数
        now = datetime.now()
        tomorrow_8am = now.replace(hour=8, minute=0, second=0, microsecond=0) + timedelta(days=1)
        sleep_seconds = (tomorrow_8am - now).total_seconds()

        #log_task("权益中心", f"下次执行时间: {tomorrow_8am.strftime('%Y-%m-%d %H:%M:%S')}")
        await asyncio.sleep(sleep_seconds)


# ==================== 主入口 ====================

async def main() -> None:
    """主函数：并发运行3个任务协程"""
    #log_info("=== 新疆移动组合任务调度器启动 ===")
    log_info(f"启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    #log_info("")

    await asyncio.gather(
        xunbao_task(),          # 寻宝心跳（15-20分钟）
        ydcj_task(),            # 抽奖心跳（15-20分钟）
        xj10086_gzh_task(),     # 权益中心（每日一次）
    )


if __name__ == "__main__":
    asyncio.run(main())
