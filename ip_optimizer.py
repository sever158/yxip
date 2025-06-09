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
    # 测试模式：PING 或 TCP
    "MODE": "TCP",
    # Ping 测试目标地址
    "PING_TARGET": "https://www.google.com/generate_204",
    # Ping 测试次数
    "PING_COUNT": 3,
    # Ping 超时时间（秒）
    "PING_TIMEOUT": 3,
    # TCP 测试端口
    "PORT": 443,
    # 延迟筛选范围（毫秒）
    "RTT_RANGE": "10~2000",
    # 最大丢包率（百分比）
    "LOSS_MAX": 30.0,
    # 并发线程数
    "THREADS": 50,
    # 随机IP池总大小
    "IP_POOL_SIZE": 100000,
    # 实际测试的IP数量
    "TEST_IP_COUNT": 1000,
    # 精选IP数量
    "TOP_IPS_LIMIT": 15,
    # Cloudflare IPv4池采集地址
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    # Cloudflare IPv4池采集地址（可单独配置）
    "CLOUDFLARE_IPS_URL_V4": "https://www.cloudflare.com/ips-v4",
    # Cloudflare IPv6池采集地址（可单独配置）
    "CLOUDFLARE_IPS_URL_V6": "https://www.cloudflare.com/ips-v6",
    # 自定义IP池文件路径
    "CUSTOM_IPS_FILE": "custom_ips.txt",
    # TCP重试次数
    "TCP_RETRY": 2,
    # 测速超时时间
    "SPEED_TIMEOUT": 3,
    # 测速URL
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",
    # 是否启用IPv4大池 1=开 0=关
    "ENABLE_IPV4_POOL": 1,
    # 是否启用IPv6大池 1=开 0=关
    "ENABLE_IPV6_POOL": 0
}

####################################################
#                    核心功能函数                   #
####################################################
def init_env():
    """
    初始化环境变量，自动补全协议头，禁用TLS警告。
    """
    for key, value in CONFIG.items():
        os.environ.setdefault(key, str(value))
    # 自动添加协议头
    for k in ["CLOUDFLARE_IPS_URL", "CLOUDFLARE_IPS_URL_V4", "CLOUDFLARE_IPS_URL_V6"]:
        url = os.getenv(k)
        if url and not url.startswith(('http://', 'https://')):
            os.environ[k] = f"https://{url}"
    urllib3.disable_warnings()

def fetch_ip_ranges():
    """
    获取IP段列表，优先使用自定义文件，否则分别采集IPv4/IPv6池。
    """
    custom_file = os.getenv('CUSTOM_IPS_FILE')
    if custom_file and os.path.exists(custom_file):
        print(f"🔧 使用自定义IP池文件: {custom_file}")
        try:
            with open(custom_file, 'r') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            print(f"🚨 读取自定义IP池失败: {e}")
    # 支持分别采集IPv4/IPv6
    v4_url = os.getenv('CLOUDFLARE_IPS_URL_V4')
    v6_url = os.getenv('CLOUDFLARE_IPS_URL_V6')
    subnets = []
    try:
        if v4_url:
            res = requests.get(v4_url, timeout=10, verify=False)
            subnets += [line for line in res.text.splitlines() if line and ':' not in line]
    except Exception as e:
        print(f"🚨 获取Cloudflare IPv4 IP段失败: {e}")
    try:
        if v6_url:
            res = requests.get(v6_url, timeout=10, verify=False)
            subnets += [line for line in res.text.splitlines() if line and ':' in line]
    except Exception as e:
        print(f"🚨 获取Cloudflare IPv6 IP段失败: {e}")
    # 兼容旧变量
    if not subnets:
        url = os.getenv('CLOUDFLARE_IPS_URL')
        try:
            res = requests.get(url, timeout=10, verify=False)
            subnets = res.text.splitlines()
        except Exception as e:
            print(f"🚨 获取Cloudflare IP段失败: {e}")
            return []
    return subnets

# 新增：根据开关筛选子网类型
def filter_subnets_by_switch(subnets):
    enable_ipv4 = int(os.getenv('ENABLE_IPV4_POOL', '1'))
    enable_ipv6 = int(os.getenv('ENABLE_IPV6_POOL', '1'))
    filtered = []
    for subnet in subnets:
        if ':' in subnet:
            if enable_ipv6:
                filtered.append(subnet)
        else:
            if enable_ipv4:
                filtered.append(subnet)
    return filtered

def generate_random_ip(subnet):
    """
    根据CIDR生成子网内的随机合法IP（支持IPv4和IPv6）。
    修正：IPv4每段最大不能超过255。
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        if network.version == 4:
            # 只允许生成合法的IPv4地址（每段0-255）
            network_addr = int(network.network_address)
            broadcast_addr = int(network.broadcast_address)
            first_ip = network_addr + 1
            last_ip = broadcast_addr - 1
            # 限制最大为255
            def valid_ipv4(ip_int):
                octets = [(ip_int >> 24) & 0xFF, (ip_int >> 16) & 0xFF, (ip_int >> 8) & 0xFF, ip_int & 0xFF]
                return all(0 <= o <= 255 for o in octets)
            # 生成合法IP
            for _ in range(10):  # 最多尝试10次
                random_ip_int = random.randint(first_ip, last_ip)
                if valid_ipv4(random_ip_int):
                    return str(ipaddress.IPv4Address(random_ip_int))
            # 如果10次都不行，直接返回网络地址
            return str(network.network_address)
        else:  # IPv6
            network_addr = int(network.network_address)
            num_hosts = network.num_addresses
            if num_hosts <= 2:
                return str(network.network_address)
            random_ip_int = network_addr + random.randint(1, num_hosts - 2)
            return str(ipaddress.IPv6Address(random_ip_int))
    except Exception as e:
        print(f"生成随机IP错误: {e}，使用简单方法生成")
        base_ip = subnet.split('/')[0]
        if ':' in base_ip:
            return base_ip
        # IPv4兜底也保证每段不大于255
        parts = base_ip.split('.')
        while len(parts) < 4:
            parts.append(str(random.randint(0, 255)))
        parts = [str(min(int(x), 255)) for x in parts[:3]] + [str(random.randint(1, 254))]
        return ".".join(parts)

def custom_ping(ip):
    """
    跨平台自定义Ping测试，返回平均延迟和丢包率。
    """
    target = urlparse(os.getenv('PING_TARGET')).netloc or os.getenv('PING_TARGET')
    count = int(os.getenv('PING_COUNT'))
    timeout = int(os.getenv('PING_TIMEOUT'))
    
    try:
        # 跨平台ping命令
        if os.name == 'nt':  # Windows
            cmd = f"ping -n {count} -w {timeout*1000} {target}"
        else:  # Linux/Mac
            cmd = f"ping -c {count} -W {timeout} -I {ip} {target}"
        
        result = subprocess.run(
            cmd, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout + 2
        )
        
        # 解析ping结果
        output = result.stdout.lower()
        
        if "100% packet loss" in output or "unreachable" in output:
            return float('inf'), 100.0  # 完全丢包
        
        # 提取延迟和丢包率
        loss_line = next((l for l in result.stdout.split('\n') if "packet loss" in l.lower()), "")
        timing_lines = [l for l in result.stdout.split('\n') if "time=" in l.lower()]
        
        # 计算丢包率
        loss_percent = 100.0
        if loss_line:
            loss_parts = loss_line.split('%')
            if loss_parts:
                try:
                    loss_percent = float(loss_parts[0].split()[-1])
                except:
                    pass
        
        # 计算平均延迟
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
    TCP连接测试，带重试机制，返回平均延迟和丢包率。
    """
    retry = int(os.getenv('TCP_RETRY', 3))
    success_count = 0
    total_rtt = 0
    
    for _ in range(retry):
        start = time.time()
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                rtt = (time.time() - start) * 1000  # 毫秒
                total_rtt += rtt
                success_count += 1
        except:
            pass
        time.sleep(0.1)  # 短暂间隔
    
    loss_rate = 100 - (success_count / retry * 100)
    avg_rtt = total_rtt / success_count if success_count > 0 else float('inf')
    return avg_rtt, loss_rate

def speed_test(ip):
    """
    对指定IP进行测速，返回Mbps。
    兼容GitHub Actions环境，修复Cloudflare测速站点直连IP速度为0的问题。
    """
    url = os.getenv('SPEED_URL')
    timeout = float(os.getenv('SPEED_TIMEOUT', 10))
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        scheme = parsed_url.scheme
        # IPv6地址需加[]
        if ':' in ip and not ip.startswith('['):
            ip_url = url.replace(host, f'[{ip}]')
        else:
            ip_url = url.replace(host, ip)
        headers = {'Host': host}
        # 使用requests的自定义适配器强制绑定IP
        session = requests.Session()
        from requests.adapters import HTTPAdapter
        import urllib3.util.connection
        import socket as pysocket

        def _patched_create_connection(address, *args, **kwargs):
            host_, port = address
            # 强制用目标IP直连
            if host_ == ip or host_ == f'[{ip}]':
                host_ = ip
            family = pysocket.AF_INET6 if ':' in ip else pysocket.AF_INET
            return pysocket.create_connection((host_, port), *args, **kwargs, family=family)
        old_create_connection = urllib3.util.connection.create_connection
        urllib3.util.connection.create_connection = _patched_create_connection

        try:
            start_time = time.time()
            response = session.get(
                ip_url,
                headers=headers,
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
            speed_mbps = (total_bytes * 8) / (duration * 1000000) if duration > 0 else 0
            return speed_mbps
        finally:
            urllib3.util.connection.create_connection = old_create_connection
    except Exception as e:
        # 降级为HTTP测速（部分测速站点支持），便于排查HTTPS证书/SNI问题
        if url.startswith("https://"):
            try:
                url_http = url.replace("https://", "http://", 1)
                parsed_url = urlparse(url_http)
                host = parsed_url.hostname
                if ':' in ip and not ip.startswith('['):
                    ip_url = url_http.replace(host, f'[{ip}]')
                else:
                    ip_url = url_http.replace(host, ip)
                headers = {'Host': host}
                start_time = time.time()
                response = requests.get(
                    ip_url,
                    headers=headers,
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
                speed_mbps = (total_bytes * 8) / (duration * 1000000) if duration > 0 else 0
                return speed_mbps
            except Exception:
                return 0.0
        return 0.0

def ping_test(ip):
    """
    IP综合测试 - 第一阶段：Ping或TCP延迟测试。
    """
    mode = os.getenv('MODE', 'PING').upper()
    
    if mode == "PING":
        # 使用自定义Ping测试
        avg_delay, loss_rate = custom_ping(ip)
        return (ip, avg_delay, loss_rate)
    
    else:  # TCP模式
        port = int(os.getenv('PORT', 443))
        avg_rtt, loss_rate = tcp_ping(ip, port, timeout=float(os.getenv('PING_TIMEOUT', 2)))
        return (ip, avg_rtt, loss_rate)

def full_test(ip_data):
    """
    IP综合测试 - 第二阶段：测速。
    """
    ip = ip_data[0]
    speed = speed_test(ip)
    return (*ip_data, speed)

####################################################
#                      主逻辑                      #
####################################################
if __name__ == "__main__":
    # 初始化环境变量
    init_env()
    print("="*60)
    print(f"{'IP网络优化器 v2.3 (IPv6大池支持)':^60}")
    print("="*60)
    # 打印主要参数
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
        print(f"自定义IP池: {custom_file}")
    else:
        print(f"Cloudflare IP源: {os.getenv('CLOUDFLARE_IPS_URL_V4')} / {os.getenv('CLOUDFLARE_IPS_URL_V6')}")
    print(f"测速URL: {os.getenv('SPEED_URL')}")
    print("="*60 + "\n")

    # 获取IP段
    subnets = fetch_ip_ranges()
    if not subnets:
        print("❌ 无法获取IP段，程序终止")
        exit(1)
    # 新增：根据开关筛选
    subnets = filter_subnets_by_switch(subnets)
    if not subnets:
        print("❌ 没有可用的IP段（请检查ENABLE_IPV4_POOL/ENABLE_IPV6_POOL配置）")
        exit(1)
    source_type = "自定义" if custom_file and os.path.exists(custom_file) else "Cloudflare"
    print(f"✅ 获取到 {len(subnets)} 个{source_type} IP段（已按开关筛选）")

    ip_pool_size = int(os.getenv('IP_POOL_SIZE'))
    test_ip_count = int(os.getenv('TEST_IP_COUNT'))

    # 多线程生成大池
    full_ip_pool = set()
    def ip_worker(_):
        while True:
            subnet = random.choice(subnets)
            ip = generate_random_ip(subnet)
            if ip not in full_ip_pool:
                return ip
    print(f"🔧 正在生成 {ip_pool_size} 个随机IP的大池（支持IPv6）...")
    with ThreadPoolExecutor(max_workers=8) as pool, tqdm(total=ip_pool_size, desc="生成IP大池", unit="IP") as pbar:
        futures = [pool.submit(ip_worker, i) for i in range(ip_pool_size)]
        for f in as_completed(futures):
            ip = f.result()
            full_ip_pool.add(ip)
            pbar.update(1)
            if len(full_ip_pool) >= ip_pool_size:
                break

    print(f"✅ 成功生成 {len(full_ip_pool)} 个随机IP的大池")
    if test_ip_count > len(full_ip_pool):
        print(f"⚠️ 警告: 测试IP数量({test_ip_count})大于IP池大小({len(full_ip_pool)})，使用全部IP")
        test_ip_count = len(full_ip_pool)
    test_ip_pool = random.sample(list(full_ip_pool), test_ip_count)
    print(f"🔧 从大池中随机选择 {len(test_ip_pool)} 个IP进行测试")

    # 3. 第一阶段：Ping测试（筛选IP）
    ping_results = []
    with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
        future_to_ip = {executor.submit(ping_test, ip): ip for ip in test_ip_pool}
        
        # 进度条配置
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
    
    # 筛选通过Ping测试的IP
    rtt_min, rtt_max = map(int, os.getenv('RTT_RANGE').split('~'))
    loss_max = float(os.getenv('LOSS_MAX'))
    
    passed_ips = [
        ip_data for ip_data in ping_results 
        if rtt_min <= ip_data[1] <= rtt_max
        and ip_data[2] <= loss_max
    ]
    
    print(f"\n✅ Ping测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips)}")
    
    # 4. 第二阶段：测速（仅对通过Ping测试的IP）
    if not passed_ips:
        print("❌ 没有通过Ping测试的IP，程序终止")
        exit(1)
    
    full_results = []
    with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
        future_to_ip = {executor.submit(full_test, ip_data): ip_data for ip_data in passed_ips}
        
        # 进度条配置
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
        key=lambda x: (-x[3], x[1])  # 先按速度降序，再按延迟升序
    )[:int(os.getenv('TOP_IPS_LIMIT', 15))]
    
    # 6. 保存结果
    results_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(results_dir, exist_ok=True)
    with open(os.path.join(results_dir, 'all_ips.txt'), 'w') as f:
        f.write("\n".join([ip[0] for ip in ping_results]))
    with open(os.path.join(results_dir, 'passed_ips.txt'), 'w') as f:
        f.write("\n".join([ip[0] for ip in passed_ips]))
    with open(os.path.join(results_dir, 'full_results.csv'), 'w') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps)\n")
        for ip_data in full_results:
            f.write(f"{ip_data[0]},{ip_data[1]:.2f},{ip_data[2]:.2f},{ip_data[3]:.2f}\n")
    with open(os.path.join(results_dir, 'top_ips.txt'), 'w') as f:
        f.write("\n".join([ip[0] for ip in sorted_ips]))
    with open(os.path.join(results_dir, 'top_ips_details.csv'), 'w') as f:
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
