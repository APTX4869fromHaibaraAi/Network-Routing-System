#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import logging
import socket

import requests
import yaml


def load_config(config_path: str) -> dict:
    """从 YAML 配置文件读取参数"""
    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f)

    if "load_balancer" not in cfg or "business" not in cfg:
        raise ValueError("配置文件缺少 load_balancer 或 business 段")

    return cfg


def resolve_lb_ip(domain: str, retry_interval: int) -> str:
    """
    用域名解析负载均衡器 IP。
    如果解析失败，就 sleep 然后一直重试，直到解析成功。
    """
    while True:
        try:
            ip = socket.gethostbyname(domain)
            logging.info(f"Resolved LB domain {domain} -> {ip}")
            return ip
        except socket.gaierror as e:
            logging.error(
                f"DNS resolve failed for {domain}: {e}, "
                f"retry in {retry_interval}s ..."
            )
            time.sleep(retry_interval)


def register_business_once(lb_ip: str,
                           lb_port: int,
                           business_id: str,
                           business_ip: str) -> bool:
    """
    向负载均衡器注册一次业务服务器信息。
    返回 True 表示本次注册成功（HTTP 2xx），否则 False。
    """
    url = f"http://{lb_ip}:{lb_port}/register_business"

    payload = {
        "business_id": business_id,
        "business_ip": business_ip,
        "timestamp": time.time(),
    }

    try:
        resp = requests.post(url, json=payload, timeout=5)
        if 200 <= resp.status_code < 300:
            logging.info(
                f"Register business OK: status={resp.status_code}, body={resp.text}"
            )
            return True
        else:
            logging.error(
                f"Register business FAIL: status={resp.status_code}, body={resp.text}"
            )
            return False
    except Exception as e:
        logging.error(f"Register business error: {e}")
        return False


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    # 默认：和脚本一个目录下的 business_config.yaml
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, "business_config.yaml")

    logging.info(f"Using config file: {config_path}")
    cfg = load_config(config_path)

    lb_domain = cfg["load_balancer"]["domain"]
    lb_port = int(cfg["load_balancer"]["port"])

    biz_cfg = cfg["business"]
    business_id = biz_cfg["id"]
    business_ip = biz_cfg["ip"]
    report_interval = int(biz_cfg.get("report_interval", 60))
    retry_interval = int(biz_cfg.get("retry_interval", 10))

    logging.info(
        f"Business ID={business_id}, IP={business_ip}, "
        f"LB domain={lb_domain}:{lb_port}, "
        f"report_interval={report_interval}s, retry_interval={retry_interval}s"
    )

    # 外层死循环：一直跑（包含 DNS 解析 + 注册）
    while True:
        # 1) 先用域名解析出 LB 的 IP
        lb_ip = resolve_lb_ip(lb_domain, retry_interval)

        # 2) 内层死循环：一直注册直到成功
        while True:
            ok = register_business_once(lb_ip, lb_port, business_id, business_ip)
            if ok:
                logging.info("First register success, enter periodic reporting loop")
                break

            logging.info(f"Register failed, retry in {retry_interval}s ...")
            time.sleep(retry_interval)

        # 3) 成功之后，按 report_interval 周期性重新上报
        while True:
            time.sleep(report_interval)
            ok = register_business_once(lb_ip, lb_port, business_id, business_ip)
            if not ok:
                logging.warning(
                    f"Periodic report failed, will re-resolve domain and retry ..."
                )
                # 出现问题就跳出这层循环，回到最外层：
                # 重新 DNS 解析，再重新“直到成功为止”注册一次
                break


if __name__ == "__main__":
    main()
