import os
import requests
import random
import numpy as np
import time
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from tqdm import tqdm
import urllib3
import ipaddress

####################################################
#                 可配置参数（程序开头）              #
####################################################
CONFIG = {
    "MODE": "TCP",                  # 测试模式：PING/TCP
    "PING_TARGET": "https://www.google.com/generate_204",  # Ping测试目标
    "PING_COUNT": 3,                # Ping次数
    "PING_TIMEOUT": 5,              # Ping超时(秒)
    "PORT": 443,                    # TCP测试端口
    "RTT_RANGE": "10~2000",         # 延迟范围(ms)
    "LOSS_MAX": 30.0,               # 最大丢包率(%)
    "THREADS": 50,                  # 并发线程数
    "IP_POOL_SIZE": 100000,         # IP池总大小
    "TEST_IP_COUNT": 1000,          # 实际测试IP数量
    "TOP_IPS_LIMIT": 15,            # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "CloudflareV4V6ip.txt",   # 本地IP池文件
    "TCP_RETRY": 2,                 # TCP重试次数
    "SPEED_TIMEOUT": 5,             # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000"  # 测速URL
}

####################################################
#                    核心功能函数                   #
####################################################
def init_env():
    """初始化环境变量和全局配置"""
    for key, value in CONFIG.items():
        os.environ.setdefault(key, str(value))
    cf_url = os.getenv('CLOUDFLARE_IPS_URL')
    if cf_url and not cf_url.startswith(('http://', 'https://')):
        os.environ['CLOUDFLARE_IPS_URL'] = f"https://{cf_url}"
    urllib3.disable_warnings()

def fetch_ip_ranges():
    """
    获取IP段列表，优先本地文件（CUSTOM_IPS_FILE），否则远程下载（CLOUDFLARE_IPS_URL）
    支持IPv4和IPv6
    """
    custom_file = os.getenv('CUSTOM_IPS_FILE')
    if custom_file and os.path.exists(custom_file):
        print(f"🔧 使用本地IP池文件: {custom_file}")
        try:
            with open(custom_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"🚨 读取本地IP池失败: {e}")
    # 远程下载
    url = os.getenv('CLOUDFLARE_IPS_URL')
    try:
        print(f"🌐 正在远程下载IP池: {url}")
        res = requests.get(url, timeout=10, verify=False)
        return [line.strip() for line in res.text.splitlines() if line.strip()]
    except Exception as e:
        print(f"🚨 获取远程IP池失败: {e}")
        return []

def generate_random_ip(subnet):
    """
    根据CIDR生成子网内的随机合法IP（支持IPv4和IPv6，排除网络和广播地址）
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        if network.num_addresses <= 2:
            return str(network.network_address)
        first_ip = int(network.network_address) + 1
        last_ip = int(network.broadcast_address) - 1
        random_ip_int = random.randint(first_ip, last_ip)
        if isinstance(network, ipaddress.IPv4Network):
            return str(ipaddress.IPv4Address(random_ip_int))
        else:
            return str(ipaddress.IPv6Address(random_ip_int))
    except Exception as e:
        print(f"生成随机IP错误: {e}")
        return subnet.split('/')[0]

def custom_ping(ip):
    """
    跨平台Ping测试，自动适配IPv4/IPv6
    返回平均延迟(ms)和丢包率(%)
    """
    is_ipv6 = ':' in ip
    target = urlparse(os.getenv('PING_TARGET')).netloc or os.getenv('PING_TARGET')
    count = int(os.getenv('PING_COUNT'))
    timeout = int(os.getenv('PING_TIMEOUT'))
    try:
        if os.name == 'nt':  # Windows
            cmd = f"ping {'-6' if is_ipv6 else ''} -n {count} -w {timeout*1000} {target}"
        else:  # Linux/Mac
            ping_bin = "ping6" if is_ipv6 else "ping"
            cmd = f"{ping_bin} -c {count} -W {timeout} {target}"
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout + 2
        )
        output = result.stdout.lower()
        if "100% packet loss" in output or "unreachable" in output:
            return float('inf'), 100.0
        loss_line = next((l for l in result.stdout.split('\n') if "packet loss" in l.lower()), "")
        timing_lines = [l for l in result.stdout.split('\n') if "time=" in l.lower()]
        loss_percent = 100.0
        if loss_line:
            loss_parts = loss_line.split('%')
            if loss_parts:
                try:
                    loss_percent = float(loss_parts[0].split()[-1])
                except:
                    pass
        delays = []
        for line in timing_lines:
            if "time=" in line:
                time_str = line.split("time=")[1].split()[0]
                try:
                    delays.append(float(time_str))
                except:
                    continue
        avg_delay = np.mean(delays) if delays else float('inf')
        return avg_delay, loss_percent
    except subprocess.TimeoutExpired:
        return float('inf'), 100.0
    except Exception as e:
        print(f"Ping测试异常: {e}")
        return float('inf'), 100.0

def tcp_ping(ip, port, timeout=2):
    """
    TCP连接测试，自动适配IPv4/IPv6，返回平均延迟(ms)和丢包率(%)
    """
    retry = int(os.getenv('TCP_RETRY', 3))
    success_count = 0
    total_rtt = 0
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    for _ in range(retry):
        start = time.time()
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))
                rtt = (time.time() - start) * 1000
                total_rtt += rtt
                success_count += 1
        except:
            pass
        time.sleep(0.1)
    loss_rate = 100 - (success_count / retry * 100)
    avg_rtt = total_rtt / success_count if success_count > 0 else float('inf')
    return avg_rtt, loss_rate

def speed_test(ip):
    """
    下载测速，自动适配IPv4/IPv6，返回Mbps
    """
    url = os.getenv('SPEED_URL')
    timeout = float(os.getenv('SPEED_TIMEOUT', 10))
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        if ':' in ip:
            url = url.replace(host, f"[{ip}]")
        else:
            url = url.replace(host, ip)
        start_time = time.time()
        response = requests.get(
            url,
            headers={'Host': host},
            timeout=timeout,
            verify=False,
            stream=True
        )
        total_bytes = 0
        for chunk in response.iter_content(chunk_size=8192):
            total_bytes += len(chunk)
            if time.time() - start_time > timeout:
                break
        duration = time.time() - start_time
        speed_mbps = (total_bytes * 8) / (duration * 1000000)
        return speed_mbps
    except Exception as e:
        print(f"测速失败 [{ip}]: {e}")
        return 0.0

def ping_test(ip):
    """
    第一阶段：延迟/丢包测试（PING或TCP）
    """
    mode = os.getenv('MODE', 'PING').upper()
    if mode == "PING":
        avg_delay, loss_rate = custom_ping(ip)
        return (ip, avg_delay, loss_rate)
    else:
        port = int(os.getenv('PORT', 443))
        avg_rtt, loss_rate = tcp_ping(ip, port, timeout=float(os.getenv('PING_TIMEOUT', 2)))
        return (ip, avg_rtt, loss_rate)

def full_test(ip_data):
    """
    第二阶段：测速
    """
    ip = ip_data[0]
    speed = speed_test(ip)
    return (*ip_data, speed)

####################################################
#                      主逻辑                      #
####################################################
if __name__ == "__main__":
    # 0. 初始化环境
    init_env()
    # 1. 打印配置参数
    print("="*60)
    print(f"{'IP网络优化器 v2.2':^60}")
    print("="*60)
    print(f"测试模式: {os.getenv('MODE')}")
    if os.getenv('MODE') == "PING":
        print(f"Ping目标: {os.getenv('PING_TARGET')}")
        print(f"Ping次数: {os.getenv('PING_COUNT')}")
        print(f"Ping超时: {os.getenv('PING_TIMEOUT')}秒")
    else:
        print(f"TCP端口: {os.getenv('PORT')}")
        print(f"TCP重试: {os.getenv('TCP_RETRY')}次")
    print(f"延迟范围: {os.getenv('RTT_RANGE')}ms")
    print(f"最大丢包: {os.getenv('LOSS_MAX')}%")
    print(f"并发线程: {os.getenv('THREADS')}")
    print(f"IP池大小: {os.getenv('IP_POOL_SIZE')}")
    print(f"测试IP数: {os.getenv('TEST_IP_COUNT')}")
    custom_file = os.getenv('CUSTOM_IPS_FILE')
    if custom_file:
        print(f"本地IP池: {custom_file}")
    print(f"Cloudflare IP源: {os.getenv('CLOUDFLARE_IPS_URL')}")
    print(f"测速URL: {os.getenv('SPEED_URL')}")
    print("="*60 + "\n")

    # 2. 获取IP段并生成随机IP池
    subnets = fetch_ip_ranges()
    if not subnets:
        print("❌ 无法获取IP段，程序终止")
        exit(1)
    source_type = "本地" if custom_file and os.path.exists(custom_file) else "远程"
    print(f"✅ 获取到 {len(subnets)} 个{source_type} IP段")

    ip_pool_size = int(os.getenv('IP_POOL_SIZE'))
    test_ip_count = int(os.getenv('TEST_IP_COUNT'))

    # 生成完整IP池
    full_ip_pool = set()
    print(f"🔧 正在生成 {ip_pool_size} 个随机IP的大池...")
    with tqdm(total=ip_pool_size, desc="生成IP大池", unit="IP") as pbar:
        while len(full_ip_pool) < ip_pool_size:
            subnet = random.choice(subnets)
            ip = generate_random_ip(subnet)
            if ip not in full_ip_pool:
                full_ip_pool.add(ip)
                pbar.update(1)
    print(f"✅ 成功生成 {len(full_ip_pool)} 个随机IP的大池")

    # 从大池中随机选择测试IP
    if test_ip_count > len(full_ip_pool):
        print(f"⚠️ 警告: 测试IP数量({test_ip_count})大于IP池大小({len(full_ip_pool)})，使用全部IP")
        test_ip_count = len(full_ip_pool)
    test_ip_pool = random.sample(list(full_ip_pool), test_ip_count)
    print(f"🔧 从大池中随机选择 {len(test_ip_pool)} 个IP进行测试")

    # 3. 第一阶段：Ping/TCP测试
    ping_results = []
    with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
        future_to_ip = {executor.submit(ping_test, ip): ip for ip in test_ip_pool}
        with tqdm(
            total=len(test_ip_pool),
            desc="🚀 Ping测试进度",
            unit="IP",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_ip):
                try:
                    ping_results.append(future.result())
                except Exception as e:
                    print(f"\n🔧 Ping测试异常: {e}")
                finally:
                    pbar.update(1)

    # 筛选通过Ping/TCP测试的IP
    rtt_min, rtt_max = map(int, os.getenv('RTT_RANGE').split('~'))
    loss_max = float(os.getenv('LOSS_MAX'))
    passed_ips = [
        ip_data for ip_data in ping_results
        if rtt_min <= ip_data[1] <= rtt_max
        and ip_data[2] <= loss_max
    ]
    print(f"\n✅ Ping测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips)}")

    # 4. 第二阶段：测速
    if not passed_ips:
        print("❌ 没有通过Ping测试的IP，程序终止")
        exit(1)
    full_results = []
    with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
        future_to_ip = {executor.submit(full_test, ip_data): ip_data for ip_data in passed_ips}
        with tqdm(
            total=len(passed_ips),
            desc="📊 测速进度",
            unit="IP",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_ip):
                try:
                    full_results.append(future.result())
                except Exception as e:
                    print(f"\n🔧 测速异常: {e}")
                finally:
                    pbar.update(1)

    # 5. 精选IP排序（按速度降序，延迟升序）
    sorted_ips = sorted(
        full_results,
        key=lambda x: (-x[3], x[1])
    )[:int(os.getenv('TOP_IPS_LIMIT', 15))]

    # 6. 保存结果
    os.makedirs('results', exist_ok=True)
    with open('results/all_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in ping_results]))
    with open('results/passed_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in passed_ips]))
    with open('results/full_results.csv', 'w') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps)\n")
        for ip_data in full_results:
            f.write(f"{ip_data[0]},{ip_data[1]:.2f},{ip_data[2]:.2f},{ip_data[3]:.2f}\n")
    with open('results/top_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in sorted_ips]))
    with open('results/top_ips_details.csv', 'w') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps)\n")
        for ip_data in sorted_ips:
            f.write(f"{ip_data[0]},{ip_data[1]:.2f},{ip_data[2]:.2f},{ip_data[3]:.2f}\n")

    # 7. 显示统计结果
    print("\n" + "="*60)
    print(f"{'🔥 测试结果统计':^60}")
    print("="*60)
    print(f"IP池大小: {ip_pool_size}")
    print(f"实际测试IP数: {len(ping_results)}")
    print(f"通过Ping测试IP数: {len(passed_ips)}")
    print(f"测速IP数: {len(full_results)}")
    print(f"精选TOP IP: {len(sorted_ips)}")
    if sorted_ips:
        print("\n🏆【最佳IP TOP5】")
        for i, ip_data in enumerate(sorted_ips[:5]):
            print(f"{i+1}. {ip_data[0]} | 延迟:{ip_data[1]:.2f}ms | 丢包:{ip_data[2]:.2f}% | 速度:{ip_data[3]:.2f}Mbps")
    print("="*60)
    print("✅ 结果已保存至 results/ 目录")
